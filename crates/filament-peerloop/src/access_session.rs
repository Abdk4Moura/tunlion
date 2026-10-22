//! Embedding adapter for an EXISTING purpose-authenticated Conn. This drives
//! real control/data transport and the one AgreementEngine; it does not allocate
//! codes, create contacts, or impersonate the still-unextracted signaling loop.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use bytes::Bytes;
use serde_json::{json,Value};
use tokio::sync::{mpsc,oneshot};
use crate::access::{AccessError,AccessSpec,AgreementEngine,AgreementSnapshot,AgreementState,AuthenticatedReview,Lifetime,ProvenPeer};
use crate::conn::Conn;
use crate::driver::Cancellation;
use crate::host::HostServices;
use crate::l2::Mux;
use crate::recv::store::OverlayKey;
use crate::send::ceremony::{Ceremony,TemporaryBinding,TemporaryRole};

/// Feed only the exact Conn/link handed to `AuthenticatedAccessConnection`.
/// Capacity is bounded; backpressure must be honored by the embedding adapter.
pub enum AccessInbound { Control(Value), Frame{sid:u32,data:Bytes}, Disconnected }
pub fn access_channel() -> (mpsc::Sender<AccessInbound>,mpsc::Receiver<AccessInbound>) { mpsc::channel(32) }

/// The exact argv/cwd/env/liveness of one agreement-scoped shell-class exec.
/// This is the existing `exec-open` vocabulary, not a second shell protocol.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ShellRequest {
    pub argv:Vec<String>,
    pub cwd:Option<std::path::PathBuf>,
    pub env:Vec<(String,String)>,
    pub alive_ms:Option<u64>,
}

/// The host's existing process primitive plus log sink, supplied by an
/// embedder that can serve shell-class exec. The access endpoint itself never
/// invents a process backend; without this runtime a shell open is refused.
#[derive(Clone)]
pub struct ShellRuntime {
    pub process:Arc<dyn crate::shell::exec::ExecProcess>,
    pub log:Arc<dyn crate::host::LogSink>,
}
impl ShellRuntime {
    pub fn new(process:Arc<dyn crate::shell::exec::ExecProcess>, log:Arc<dyn crate::host::LogSink>) -> Self {
        Self { process, log }
    }
}

/// One live agreement-scoped shell/exec session on the initiator side.
///
/// Bytes written with [`write`](Self::write) ride `sid`; stdout arrives on
/// `stdout`, stderr on `err_sid` through `stderr`. `control` carries the
/// existing `exec-close`/`exec-alive-ack` frames. Dropping this handle closes
/// only its own two stream ids; End/removal on the host tears down the process.
pub struct AccessShell {
    pub sid:u32,
    pub err_sid:u32,
    pub transport:Arc<dyn filament_transport::net::Transport>,
    pub stdout:Option<mpsc::Receiver<crate::l2::PipeItem>>,
    pub stderr:Option<mpsc::Receiver<crate::l2::PipeItem>>,
    pub control:Option<mpsc::Receiver<Value>>,
    mux:Arc<Mux>,generation:u64,err_generation:u64,
}
impl AccessShell {
    /// Send stdin bytes on the existing exec stdin stream.
    pub async fn write(&self,bytes:&[u8])->Result<(),AccessError>{
        self.transport.send_frame(self.sid,0,bytes).await.map_err(|_|AccessError::Unavailable)
    }
    /// Signal stdin EOF using the existing empty-frame convention.
    pub async fn eof(&self)->Result<(),AccessError>{
        self.transport.send_frame(self.sid,0,&[]).await.map_err(|_|AccessError::Unavailable)
    }
    /// Forward the user's signal on the existing exec control channel.
    pub async fn signal(&self,signal:&str)->Result<(),AccessError>{
        self.transport.send_control(&json!({"type":"exec-signal","sid":self.sid,"signal":signal})).await.map_err(|_|AccessError::Unavailable)
    }
    /// Keepalive; only needed when the open announced `alive_ms`.
    pub async fn alive(&self)->Result<(),AccessError>{
        self.transport.send_control(&json!({"type":"exec-alive","sid":self.sid})).await.map_err(|_|AccessError::Unavailable)
    }
}
impl Drop for AccessShell {
    fn drop(&mut self){
        if let Ok(rt)=tokio::runtime::Handle::try_current(){
            let mux=self.mux.clone();let sid=self.sid;let err_sid=self.err_sid;
            let generation=self.generation;let err_generation=self.err_generation;
            rt.spawn(async move{
                mux.drop_stream_if(sid,generation).await;
                mux.drop_stream_if(err_sid,err_generation).await;
                let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid})).await;
            });
        }
    }
}

pub struct AuthenticatedAccessConnection {
    ceremony:Ceremony,
    transport:Arc<dyn filament_transport::net::Transport>,
    incoming:mpsc::Receiver<AccessInbound>,
}
impl AuthenticatedAccessConnection {
    pub async fn from_conn(ceremony:Ceremony,conn:&Conn,pid:&str,incoming:mpsc::Receiver<AccessInbound>)->Result<Self,AccessError> {
        let peer=conn.link(pid).and_then(|link|link.peer.as_ref()).ok_or(AccessError::Unavailable)?;
        let (mine,theirs)=peer.fingerprints().await.ok_or(AccessError::InvalidProof)?;
        if !ceremony.confirmed_temporary_transport(&mine,&theirs) { return Err(AccessError::InvalidProof); }
        let transport=conn.transport_of(pid).ok_or(AccessError::Unavailable)?;
        Ok(Self{ceremony,transport,incoming})
    }
}

#[derive(Clone,Debug)]
pub struct AccessOfferDraft { pub binding:TemporaryBinding,pub spec:AccessSpec,pub lifetime:Lifetime,pub claim_expires_at:u64,pub label:String }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum AccessPhase { Authenticating,Review,AwaitingAcceptance,Active,Ending,Ended,Failed }
#[derive(Clone,Debug)]
pub struct AccessView { pub phase:AccessPhase,pub agreement:Option<AgreementSnapshot>,pub peer_acknowledged_end:bool,pub failure:Option<String> }
#[derive(Clone,Debug)]
pub struct AccessSessionEvent { pub sequence:u64,pub view:AccessView }
#[derive(Clone,Debug)]
pub struct AccessSessionEvents { pub latest:u64,pub reset_required:bool,pub events:Vec<AccessSessionEvent> }
struct Observed { view:AccessView,sequence:u64,events:VecDeque<AccessSessionEvent> }
#[derive(Clone)]
pub struct AccessObserver(Arc<Mutex<Observed>>);
impl AccessObserver {
    pub fn snapshot(&self)->Result<AccessView,AccessError>{Ok(self.0.lock().map_err(|_|AccessError::Poisoned)?.view.clone())}
    pub fn events(&self,after:u64)->Result<AccessSessionEvents,AccessError>{
        let state=self.0.lock().map_err(|_|AccessError::Poisoned)?;
        Ok(AccessSessionEvents{latest:state.sequence,reset_required:after>state.sequence || state.events.front().is_some_and(|e|after.saturating_add(1)<e.sequence),events:state.events.iter().filter(|e|e.sequence>after).cloned().collect()})
    }
    fn publish(&self,view:AccessView){if let Ok(mut s)=self.0.lock(){s.sequence+=1;s.view=view.clone();let sequence=s.sequence;s.events.push_back(AccessSessionEvent{sequence,view});if s.events.len()>128{s.events.pop_front();}}}
}
type Reply=oneshot::Sender<Result<AgreementSnapshot,AccessError>>;
type OpenReply=oneshot::Sender<Result<AccessPipe,AccessError>>;
type ShellReply=oneshot::Sender<Result<AccessShell,AccessError>>;
enum Command { Accept(u64,Reply),Update(u64,AccessSpec,Lifetime,Reply),End(Reply),Open(u64,String,bool,OpenReply),OpenShell(u64,ShellRequest,ShellReply) }
/// Own this pipe for the entire operation. Dropping it closes only its own SID.
pub struct AccessPipe {
    pub sid:u32,pub transport:Arc<dyn filament_transport::net::Transport>,
    pub stream:Option<mpsc::Receiver<crate::l2::PipeItem>>,
    #[cfg(feature="mount-server")] pub folder_caps:Option<crate::mount_proto::MountCaps>,
    mux:Arc<Mux>,generation:u64,
}
impl Drop for AccessPipe{fn drop(&mut self){if let Ok(rt)=tokio::runtime::Handle::try_current(){let mux=self.mux.clone();let sid=self.sid;let generation=self.generation;rt.spawn(async move{mux.drop_stream_if(sid,generation).await;let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid})).await;});}}}
struct PendingOpen { reply:OpenReply,stream:mpsc::Receiver<crate::l2::PipeItem>,generation:u64,folder:bool }
struct PendingShell {
    reply:ShellReply,
    stdout:mpsc::Receiver<crate::l2::PipeItem>,
    stderr:mpsc::Receiver<crate::l2::PipeItem>,
    control:mpsc::Receiver<Value>,
    err_sid:u32,generation:u64,err_generation:u64,
}
struct Client { tx:mpsc::Sender<Command>,stop:Cancellation,observer:AccessObserver }
impl Drop for Client {fn drop(&mut self){self.stop.cancel();}}
#[derive(Clone)]
pub struct AccessHandle(Arc<Client>);
impl AccessHandle {
    pub fn observer(&self)->AccessObserver{self.0.observer.clone()}
    pub fn snapshot(&self)->Result<AccessView,AccessError>{self.0.observer.snapshot()}
    pub fn events(&self,after:u64)->Result<AccessSessionEvents,AccessError>{self.0.observer.events(after)}
    async fn command(&self,make:impl FnOnce(Reply)->Command)->Result<AgreementSnapshot,AccessError>{
        let (tx,rx)=oneshot::channel();
        self.0.tx.send(make(tx)).await.map_err(|_|AccessError::Ended)?;
        tokio::time::timeout(Duration::from_secs(10),rx).await.map_err(|_|AccessError::Unavailable)?.map_err(|_|AccessError::Ended)?
    }
    pub async fn accept(&self,revision:u64)->Result<AgreementSnapshot,AccessError>{self.command(|tx|Command::Accept(revision,tx)).await}
    pub async fn update(&self,revision:u64,spec:AccessSpec,lifetime:Lifetime)->Result<AgreementSnapshot,AccessError>{self.command(|tx|Command::Update(revision,spec,lifetime,tx)).await}
    /// Returns after LOCAL revocation and resource cleanup, not a promise that
    /// the peer acknowledged. Inspect `peer_acknowledged_end` independently.
    pub async fn end(&self)->Result<AgreementSnapshot,AccessError>{
        let view=self.snapshot()?;
        if matches!(view.phase,AccessPhase::Ending|AccessPhase::Ended){return view.agreement.ok_or(AccessError::NotFound);}
        self.command(Command::End).await
    }
    pub async fn open_service(&self,revision:u64,resource:String)->Result<AccessPipe,AccessError>{self.open(revision,resource,false).await}
    pub async fn open_folder(&self,revision:u64,resource:String)->Result<AccessPipe,AccessError>{self.open(revision,resource,true).await}
    /// Open the accepted agreement's shell resource through the existing exec
    /// protocol. The host re-checks agreement/revision/peer/shell scope itself;
    /// this call passing `revision` is not an authorization claim.
    pub async fn open_shell(&self,revision:u64,request:ShellRequest)->Result<AccessShell,AccessError>{
        let(tx,rx)=oneshot::channel();self.0.tx.send(Command::OpenShell(revision,request,tx)).await.map_err(|_|AccessError::Ended)?;
        tokio::time::timeout(Duration::from_secs(10),rx).await.map_err(|_|AccessError::Unavailable)?.map_err(|_|AccessError::Ended)?
    }
    async fn open(&self,revision:u64,resource:String,folder:bool)->Result<AccessPipe,AccessError>{
        let(tx,rx)=oneshot::channel();self.0.tx.send(Command::Open(revision,resource,folder,tx)).await.map_err(|_|AccessError::Ended)?;
        tokio::time::timeout(Duration::from_secs(10),rx).await.map_err(|_|AccessError::Unavailable)?.map_err(|_|AccessError::Ended)?
    }
}

/// Start through the owning Core's existing Engine/stop/readiness lifecycle.
pub struct AccessDispatch {
    connection:AuthenticatedAccessConnection,key:OverlayKey,host:Arc<dyn HostServices>,
    draft:Option<AccessOfferDraft>,commands:mpsc::Receiver<Command>,stop:Cancellation,observer:AccessObserver,
    engine:Option<Arc<AgreementEngine>>,peer:Option<ProvenPeer>,review:Option<AuthenticatedReview>,snapshot:Option<AgreementSnapshot>,
    mux:Arc<Mux>,tasks:tokio::task::JoinSet<()>,ending:bool,
    pending_accept:Option<(u64,Reply)>,pending_opens:std::collections::BTreeMap<u32,PendingOpen>,
    pending_shells:std::collections::BTreeMap<u32,PendingShell>,shell:Option<ShellRuntime>,
}
impl AccessDispatch {
    pub fn new(connection:AuthenticatedAccessConnection,key:OverlayKey,host:Arc<dyn HostServices>,draft:Option<AccessOfferDraft>,names:Vec<String>)->Result<(Self,AccessHandle),AccessError>{
        Self::new_with_shell(connection,key,host,draft,names,None)
    }
    /// Same session, with the embedder's existing process primitive available
    /// for agreement-scoped shell serving. A host that offers `spec.shell` must
    /// supply this; otherwise the offer fails closed instead of advertising an
    /// endpoint it cannot serve.
    pub fn new_with_shell(connection:AuthenticatedAccessConnection,key:OverlayKey,host:Arc<dyn HostServices>,draft:Option<AccessOfferDraft>,names:Vec<String>,shell:Option<ShellRuntime>)->Result<(Self,AccessHandle),AccessError>{
        let local=key.public_key_bytes().map_err(|_|AccessError::Unavailable)?;
        let binding=connection.ceremony.temporary_binding().ok_or(AccessError::InvalidProof)?;
        let role=connection.ceremony.temporary_role().ok_or(AccessError::InvalidProof)?;
        match (&draft,role){
            (Some(d),TemporaryRole::Host) if d.binding==*binding && binding.host_peer==local && d.binding.digest_for(&d.spec,d.lifetime,d.claim_expires_at)?==binding.offer_digest=>{},
            (None,TemporaryRole::Recipient) if binding.host_peer!=local=>{},
            _=>return Err(AccessError::InvalidProof),
        }
        if draft.as_ref().is_some_and(|d|d.spec.shell)&&shell.is_none(){return Err(AccessError::Unsupported);}
        // No standard token backend exists off Unix; do not advertise shell.
        #[cfg(not(unix))]
        if draft.as_ref().is_some_and(|d|d.spec.shell){return Err(AccessError::Unsupported);}
        let observer=AccessObserver(Arc::new(Mutex::new(Observed{view:AccessView{phase:AccessPhase::Authenticating,agreement:None,peer_acknowledged_end:false,failure:None},sequence:0,events:VecDeque::new()})));
        let (tx,commands)=mpsc::channel(8);let stop=Cancellation::default();
        let handle=AccessHandle(Arc::new(Client{tx,stop:stop.clone(),observer:observer.clone()}));
        let engine=draft.as_ref().map(|_|Arc::new(AgreementEngine::new(local,names)));
        let mux=Mux::new(connection.transport.clone(),host.clone());
        Ok((Self{connection,key,host,draft,commands,stop,observer,engine,peer:None,review:None,snapshot:None,mux,tasks:tokio::task::JoinSet::new(),ending:false,pending_accept:None,pending_opens:std::collections::BTreeMap::new(),pending_shells:std::collections::BTreeMap::new(),shell},handle))
    }
    fn view(&self,phase:AccessPhase,ack:bool,failure:Option<String>){self.observer.publish(AccessView{phase,agreement:self.snapshot.clone(),peer_acknowledged_end:ack,failure});}
    async fn send(&self,payload:Value)->Result<(),AccessError>{
        tokio::time::timeout(Duration::from_secs(5),self.connection.transport.send_control(&payload)).await.map_err(|_|AccessError::Unavailable)?.map_err(|_|AccessError::Unavailable)
    }
    async fn send_review(&self)->Result<(),AccessError>{
        let s=self.snapshot.as_ref().ok_or(AccessError::NotFound)?;let engine=self.engine.as_ref().ok_or(AccessError::Unsupported)?;
        let bytes=engine.review_message(&s.id,s.revision,self.host.now_secs())?;
        let signature=self.key.sign(&bytes).map_err(|_|AccessError::Unavailable)?;
        self.send(json!({"type":"access-offer","v":1,"snapshot":s,"signature":hex::encode(signature)})).await
    }
    async fn cleanup(&mut self){
        if let (Some(engine),Some(s))=(&self.engine,&self.snapshot){if let Ok(ended)=engine.end(&s.id,self.host.now_secs()){self.snapshot=Some(ended);}}
        self.tasks.shutdown().await;self.mux.shutdown_all().await;
        if let Some((_,reply))=self.pending_accept.take(){let _=reply.send(Err(AccessError::Ended));}
        for(_,pending)in std::mem::take(&mut self.pending_opens){let _=pending.reply.send(Err(AccessError::Ended));}
        for(_,pending)in std::mem::take(&mut self.pending_shells){let _=pending.reply.send(Err(AccessError::Ended));}
        if let Some(s)=&mut self.snapshot{if !matches!(s.state,AgreementState::Ended|AgreementState::Expired|AgreementState::Declined){s.state=AgreementState::Ended;s.accepted_revision=None;}}
    }
    pub async fn drive(mut self,core_stop:Cancellation)->Result<(),AccessError>{
        let result=self.run(&core_stop).await;
        self.cleanup().await;
        if let Some(s)=&mut self.snapshot{if !matches!(s.state,AgreementState::Ended|AgreementState::Expired|AgreementState::Declined){s.state=AgreementState::Ended;s.accepted_revision=None;}}
        let acknowledged=self.observer.snapshot().map(|v|v.peer_acknowledged_end).unwrap_or(false);
        self.view(if result.is_ok(){AccessPhase::Ended}else{AccessPhase::Failed},acknowledged,result.as_ref().err().map(ToString::to_string));
        result
    }
    async fn run(&mut self,core_stop:&Cancellation)->Result<(),AccessError>{
        let role=self.connection.ceremony.temporary_role().ok_or(AccessError::InvalidProof)?;
        if role==TemporaryRole::Recipient{self.send_proof().await?;}
        let mut tick=tokio::time::interval(Duration::from_millis(100));
        let proof_deadline=tokio::time::Instant::now()+Duration::from_secs(120);let mut end_deadline=None;
        loop{
            let stop=self.stop.clone();let core_stop=core_stop.clone();
            tokio::select!{
                biased;
                _=stop.run(std::future::pending::<()>())=>{self.cleanup().await;if let Some(s)=&self.snapshot{let _=self.send(json!({"type":"access-end","v":1,"id":s.id})).await;}return Ok(());},
                _=core_stop.run(std::future::pending::<()>())=>{self.cleanup().await;if let Some(s)=&self.snapshot{let _=self.send(json!({"type":"access-end","v":1,"id":s.id})).await;}return Ok(());},
                command=self.commands.recv()=>match command{
                    None=>return Ok(()),
                    Some(Command::End(reply))=>{
                        self.ending=true;self.cleanup().await;self.view(AccessPhase::Ending,false,None);
                        let result=self.snapshot.clone().ok_or(AccessError::NotFound);let _=reply.send(result);
                        if let Some(s)=&self.snapshot{self.send(json!({"type":"access-end","v":1,"id":s.id})).await?;}
                        end_deadline=Some(tokio::time::Instant::now()+Duration::from_secs(5));
                    },
                    Some(Command::Accept(revision,reply))=>{
                        if self.pending_accept.is_some(){let _=reply.send(Err(AccessError::Capacity));continue;}
                        let result=if self.ending{Err(AccessError::Ended)}else if let Some(review)=&self.review{
                            if review.snapshot().revision!=revision{Err(AccessError::StaleRevision)}else{
                                let signature=self.key.sign(&review.acceptance_message()?).map_err(|_|AccessError::Unavailable)?;
                                self.send(json!({"type":"access-accept","v":1,"id":review.snapshot().id,"revision":revision,"signature":hex::encode(signature)})).await?;
                                self.view(AccessPhase::AwaitingAcceptance,false,None);Ok(review.snapshot().clone())
                            }
                        }else{Err(AccessError::Unsupported)};
                        match result{Ok(_)=>self.pending_accept=Some((revision,reply)),Err(error)=>{let _=reply.send(Err(error));}}
                    },
                    Some(Command::Open(revision,resource,folder,reply))=>{
                        let result=self.begin_open(revision,&resource,folder).await;
                        match result{Ok((sid,stream,generation))=>{self.pending_opens.insert(sid,PendingOpen{reply,stream,generation,folder});},Err(error)=>{let _=reply.send(Err(error));}}
                    },
                    Some(Command::OpenShell(revision,request,reply))=>{
                        let result=self.begin_shell(revision,&request).await;
                        match result{Ok((sid,err_sid,stdout,stderr,control,generation,err_generation))=>{self.pending_shells.insert(sid,PendingShell{reply,stdout,stderr,control,err_sid,generation,err_generation});},Err(error)=>{let _=reply.send(Err(error));}}
                    },
                    Some(Command::Update(revision,spec,lifetime,reply))=>{
                        let result=if self.ending{Err(AccessError::Ended)}else if let (Some(engine),Some(s))=(&self.engine,&self.snapshot){engine.revise(&s.id,revision,spec,lifetime,self.host.now_secs())}else{Err(AccessError::Unsupported)};
                        if let Ok(s)=&result{self.snapshot=Some(s.clone());self.send_review().await?;self.view(AccessPhase::AwaitingAcceptance,false,None);}
                        let _=reply.send(result);
                    },
                },
                event=self.connection.incoming.recv()=>match event{
                    Some(AccessInbound::Frame{sid,data})=>self.mux.on_frame(sid,data).await,
                    Some(AccessInbound::Control(payload))=>if self.control(payload).await?{return Ok(());},
                    Some(AccessInbound::Disconnected)|None=>return Err(AccessError::Unavailable),
                },
                _=tick.tick()=>{
                    if self.connection.transport.is_dead(){return Err(AccessError::Unavailable);}
                    if self.peer.is_some_and(|peer|self.host.delegated_access_for(&peer.public_key()).is_some()){return Err(AccessError::Unsupported);}
                    let abandoned:Vec<_>=self.pending_opens.iter().filter(|(_,open)|open.reply.is_closed()).map(|(sid,_)|*sid).collect();
                    for sid in abandoned{if let Some(open)=self.pending_opens.remove(&sid){self.mux.drop_stream_if(sid,open.generation).await;let _=self.send(json!({"type":"l2-close","sid":sid})).await;}}
                    let abandoned_shells:Vec<_>=self.pending_shells.iter().filter(|(_,open)|open.reply.is_closed()).map(|(sid,_)|*sid).collect();
                    for sid in abandoned_shells{if let Some(open)=self.pending_shells.remove(&sid){self.mux.drop_stream_if(sid,open.generation).await;self.mux.drop_stream_if(open.err_sid,open.err_generation).await;let _=self.send(json!({"type":"l2-close","sid":sid})).await;}}
                    if self.pending_accept.as_ref().is_some_and(|(_,reply)|reply.is_closed()){return Err(AccessError::Unavailable);}
                    if end_deadline.is_some_and(|at|tokio::time::Instant::now()>=at){return Ok(());}
                    if self.snapshot.is_none() && tokio::time::Instant::now()>=proof_deadline{return Err(AccessError::Expired);}
                    if let (Some(engine),Some(s))=(&self.engine,&self.snapshot){let latest=engine.snapshot(&s.id,self.host.now_secs())?;if matches!(latest.state,AgreementState::Expired|AgreementState::Ended|AgreementState::Declined)&&!self.ending{self.snapshot=Some(latest);return Ok(());}}
                },
                _=self.tasks.join_next(),if !self.tasks.is_empty()=>{},
            }
        }
    }
    async fn send_proof(&self)->Result<(),AccessError>{
        let local=self.key.public_key_bytes().map_err(|_|AccessError::Unavailable)?;
        let remote=self.peer.map(ProvenPeer::public_key).unwrap_or(self.connection.ceremony.temporary_binding().ok_or(AccessError::InvalidProof)?.host_peer);
        let bytes=self.connection.ceremony.temporary_possession_message(local,remote)?;
        let signature=self.key.sign(&bytes).map_err(|_|AccessError::Unavailable)?;
        self.send(self.connection.ceremony.temporary_proof_payload(local,remote,signature)?).await
    }
    async fn begin_open(&self,revision:u64,resource:&str,folder:bool)->Result<(u32,mpsc::Receiver<crate::l2::PipeItem>,u64),AccessError>{
        if self.ending{return Err(AccessError::Ended);}if self.engine.is_some(){return Err(AccessError::Unsupported);}
        let s=self.snapshot.as_ref().ok_or(AccessError::NotAccepted)?;
        if s.state!=AgreementState::Active || s.accepted_revision!=Some(revision){return Err(AccessError::NotAccepted);}
        if s.revision!=revision{return Err(AccessError::StaleRevision);}
        let in_scope=if folder{s.spec.folders.iter().any(|f|f.id==resource)}else{s.spec.services.iter().any(|service|service.id==resource&&service.protocol==crate::access::ServiceProtocol::Tcp)};
        if !in_scope{return Err(AccessError::InvalidSpec);}
        if self.pending_opens.len()>=crate::l2::MAX_STREAMS_PER_LINK{return Err(AccessError::Capacity);}
        let sid=self.mux.alloc_sid();let(stream,generation)=self.mux.register_access_stream(sid).await.ok_or(AccessError::Capacity)?;
        if let Err(error)=self.send(json!({"type":"access-open","v":1,"id":s.id,"revision":revision,"resource":resource,"sid":sid,"kind":if folder{"folder"}else{"tcp"}})).await{self.mux.drop_stream_if(sid,generation).await;return Err(error);}
        Ok((sid,stream,generation))
    }
    async fn begin_shell(&self,revision:u64,request:&ShellRequest)->Result<(u32,u32,mpsc::Receiver<crate::l2::PipeItem>,mpsc::Receiver<crate::l2::PipeItem>,mpsc::Receiver<Value>,u64,u64),AccessError>{
        if self.ending{return Err(AccessError::Ended);}if self.engine.is_some(){return Err(AccessError::Unsupported);}
        let s=self.snapshot.as_ref().ok_or(AccessError::NotAccepted)?;
        if s.state!=AgreementState::Active || s.accepted_revision!=Some(revision){return Err(AccessError::NotAccepted);}
        if s.revision!=revision{return Err(AccessError::StaleRevision);}
        if !s.spec.shell{return Err(AccessError::InvalidSpec);}
        if self.pending_opens.len()+self.pending_shells.len()>=crate::l2::MAX_STREAMS_PER_LINK{return Err(AccessError::Capacity);}
        let sid=self.mux.alloc_sid();let err_sid=self.mux.alloc_sid();
        if sid==err_sid{return Err(AccessError::Unavailable);}
        let mut frame=json!({"type":"access-open","v":1,"id":s.id,"revision":revision,"sid":sid,"kind":"shell","err_sid":err_sid,"argv":request.argv.clone()});
        if let Some(cwd)=&request.cwd{let Some(cwd)=cwd.to_str()else{return Err(AccessError::InvalidSpec);};frame["cwd"]=json!(cwd);}
        if !request.env.is_empty(){frame["env"]=json!(request.env.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>());}
        if let Some(alive)=request.alive_ms{frame["alive_ms"]=json!(alive);}
        // Apply the ONE existing exec frame bounds/policy before anything is
        // registered or sent; the host parses the same vocabulary again.
        crate::shell::exec::parse_exec_open(&frame).ok_or(AccessError::InvalidSpec)?;
        let (stdout,generation)=self.mux.register_access_stream(sid).await.ok_or(AccessError::Capacity)?;
        let (stderr,err_generation)=match self.mux.register_access_stream(err_sid).await{
            Some(stream)=>stream,
            None=>{self.mux.drop_stream_if(sid,generation).await;return Err(AccessError::Capacity);}
        };
        let control=self.mux.register_exec_initiator(sid).await;
        if let Err(error)=self.send(frame).await{
            self.mux.drop_stream_if(sid,generation).await;
            self.mux.drop_stream_if(err_sid,err_generation).await;
            return Err(error);
        }
        Ok((sid,err_sid,stdout,stderr,control,generation,err_generation))
    }
    async fn control(&mut self,payload:Value)->Result<bool,AccessError>{
        if serde_json::to_vec(&payload).map_err(|_|AccessError::InvalidSpec)?.len()>128*1024{return Err(AccessError::Capacity);}
        let kind=payload["type"].as_str().ok_or(AccessError::InvalidSpec)?;
        if kind=="l2-close"{if let Some(sid)=crate::l2::wire_sid(&payload){self.mux.on_close(sid,payload["err"].as_str()).await;if let Some(open)=self.pending_opens.remove(&sid){let _=open.reply.send(Err(AccessError::Unavailable));}if let Some(open)=self.pending_shells.remove(&sid){self.mux.drop_stream_if(sid,open.generation).await;self.mux.drop_stream_if(open.err_sid,open.err_generation).await;let _=open.reply.send(Err(AccessError::Unavailable));}}return Ok(false);}
        if matches!(kind,"l2-open-ack"|"mount-open-ack"){
            let sid=crate::l2::wire_sid(&payload).ok_or(AccessError::InvalidSpec)?;
            if let Some(open)=self.pending_opens.remove(&sid){
                if open.folder!=(kind=="mount-open-ack"){self.mux.drop_stream_if(sid,open.generation).await;let _=open.reply.send(Err(AccessError::InvalidSpec));return Ok(false);}
                #[cfg(feature="mount-server")]
                let folder_caps=if open.folder{Some(crate::mount_proto::parse_mount_caps(payload["caps"].clone()).map_err(|_|AccessError::InvalidSpec)?)}else{None};
                #[cfg(not(feature="mount-server"))]
                if open.folder{self.mux.drop_stream_if(sid,open.generation).await;let _=open.reply.send(Err(AccessError::Unsupported));return Ok(false);}
                let pipe=AccessPipe{sid,transport:self.mux.transport(),stream:Some(open.stream),mux:self.mux.clone(),generation:open.generation,#[cfg(feature="mount-server")]folder_caps};
                let _=open.reply.send(Ok(pipe));
            }return Ok(false);
        }
        // An agreement shell open completes on the EXISTING exec-open-ack (the
        // exec server announces stdout=sid and the initiator's stderr sid).
        if kind=="exec-open-ack"{
            let sid=crate::l2::wire_sid(&payload).ok_or(AccessError::InvalidSpec)?;
            if let Some(open)=self.pending_shells.remove(&sid){
                let ack_err=payload["err"].as_u64().and_then(|v|u32::try_from(v).ok());
                if ack_err!=Some(open.err_sid){
                    self.mux.drop_stream_if(sid,open.generation).await;
                    self.mux.drop_stream_if(open.err_sid,open.err_generation).await;
                    let _=open.reply.send(Err(AccessError::InvalidSpec));
                }else{
                    let shell=AccessShell{sid,err_sid:open.err_sid,transport:self.mux.transport(),stdout:Some(open.stdout),stderr:Some(open.stderr),control:Some(open.control),mux:self.mux.clone(),generation:open.generation,err_generation:open.err_generation};
                    let _=open.reply.send(Ok(shell));
                }
            }return Ok(false);
        }
        if matches!(kind,"exec-close"|"exec-alive-ack"){
            if let Some(sid)=crate::l2::wire_sid(&payload){self.mux.on_exec_initiator_frame(sid,payload.clone()).await;}
            return Ok(false);
        }
        // Initiator heartbeats/signals reach only a live exec session on THIS
        // peer's mux; the answer goes back on the same authenticated link.
        if matches!(kind,"exec-alive"|"exec-signal"){
            if let (Some(sid),Some(msg))=(crate::l2::wire_sid(&payload),crate::l2::mux::ExecCtl::from_frame(&payload)){
                let live=self.mux.exec_control(sid,msg).await;
                if live&&msg==crate::l2::mux::ExecCtl::Alive{let _=self.send(json!({"type":"exec-alive-ack","sid":sid})).await;}
            }
            return Ok(false);
        }
        if payload["v"].as_u64()!=Some(1){return Err(AccessError::Unsupported);}
        let local=self.key.public_key_bytes().map_err(|_|AccessError::Unavailable)?;
        if kind=="access-possession"{
            let peer=self.connection.ceremony.authenticate_temporary_payload(local,&payload)?;
            // Temporary scope must not turn an already-known delegated
            // principal into an unrestricted pairwise grant. The signed-ceiling
            // adapter is not composed here, so refuse that mode explicitly.
            if self.host.delegated_access_for(&peer.public_key()).is_some(){return Err(AccessError::Unsupported);}
            if self.peer.is_some_and(|old|old.public_key()!=peer.public_key()){return Err(AccessError::WrongPeer);}
            if self.peer.is_some(){return Ok(false);}self.peer=Some(peer);
            if let Some(draft)=self.draft.take(){
                self.send_proof().await?;
                let s=self.engine.as_ref().ok_or(AccessError::Unsupported)?.offer_bound(peer,&draft.binding,&draft.label,draft.spec,draft.lifetime,draft.claim_expires_at,self.host.now_secs())?;
                self.snapshot=Some(s);self.send_review().await?;self.view(AccessPhase::AwaitingAcceptance,false,None);
            }return Ok(false);
        }
        let peer=self.peer.ok_or(AccessError::InvalidProof)?;
        if kind=="access-offer" && self.engine.is_none(){
            if self.ending{return Ok(false);}let snapshot:AgreementSnapshot=serde_json::from_value(payload["snapshot"].clone()).map_err(|_|AccessError::InvalidSpec)?;
            let signature=signature(&payload)?;
            let review=if let Some(old)=&self.review{old.review_revision(snapshot,signature,self.host.now_secs())?}else{self.connection.ceremony.review_temporary_offer(snapshot,signature,local,self.host.now_secs())?};
            self.snapshot=Some(review.snapshot().clone());self.review=Some(review);self.view(AccessPhase::Review,false,None);return Ok(false);
        }
        let current=self.snapshot.as_ref().ok_or(AccessError::NotFound)?;
        if payload["id"].as_str()!=Some(&current.id){return Err(AccessError::NotFound);}
        match kind{
            "access-end"=>{self.ending=true;self.cleanup().await;let _=self.send(json!({"type":"access-end-ack","v":1,"id":payload["id"]})).await;self.view(AccessPhase::Ended,false,None);return Ok(true);},
            "access-end-ack" if self.ending=>{self.view(AccessPhase::Ended,true,None);return Ok(true);},
            "access-accept" if self.engine.is_some() && !self.ending=>{
                if self.host.delegated_access_for(&peer.public_key()).is_some(){return Err(AccessError::Unsupported);}
                let revision=payload["revision"].as_u64().ok_or(AccessError::InvalidSpec)?;
                let s=self.engine.as_ref().ok_or(AccessError::Unsupported)?.accept(&current.id,revision,peer,signature(&payload)?,self.host.now_secs())?;
                self.send(json!({"type":"access-active","v":1,"id":s.id,"revision":s.revision})).await?;self.snapshot=Some(s);self.view(AccessPhase::Active,false,None);
            },
            "access-active" if self.engine.is_none() && !self.ending=>{
                if payload["revision"].as_u64()!=Some(current.revision){return Err(AccessError::StaleRevision);}
                if current.state==AgreementState::Active&&current.accepted_revision==Some(current.revision){return Ok(false);}
                if self.pending_accept.as_ref().map(|(revision,_)|*revision)!=Some(current.revision){return Err(AccessError::NotAccepted);}
                let mut s=current.clone();s.state=AgreementState::Active;s.accepted_revision=Some(s.revision);self.snapshot=Some(s);self.view(AccessPhase::Active,false,None);
                if let Some((_,reply))=self.pending_accept.take(){let _=reply.send(self.snapshot.clone().ok_or(AccessError::NotFound));}
            },
            "access-open" if self.engine.is_some() && !self.ending=>{
                if self.host.delegated_access_for(&peer.public_key()).is_some(){return Err(AccessError::Unsupported);}
                let revision=payload["revision"].as_u64().ok_or(AccessError::InvalidSpec)?;let sid=crate::l2::wire_sid(&payload).ok_or(AccessError::InvalidSpec)?;
                if self.tasks.len()>=crate::l2::MAX_STREAMS_PER_LINK{return Err(AccessError::Capacity);}
                let engine=self.engine.as_ref().ok_or(AccessError::Unsupported)?.clone();
                let id=current.id.clone();let mux=self.mux.clone();let host=self.host.clone();
                match payload["kind"].as_str().unwrap_or("tcp"){
                    "shell"=>{
                        #[cfg(feature="exec-server")]
                        {
                            let Some(runtime)=self.shell.clone()else{
                                let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"shell is not available in this build"})).await;
                                return Ok(false);
                            };
                            let request=crate::shell::exec::parse_exec_open(&payload).ok_or(AccessError::InvalidSpec)?;
                            self.tasks.spawn(async move{let result=engine.serve_shell(&id,revision,peer,sid,request,mux.clone(),host,runtime.process,runtime.log).await;if let Err(error)=result{let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;}});
                        }
                        #[cfg(not(feature="exec-server"))]
                        {
                            let _=(engine,id,revision,peer,host);
                            let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":"exec receive is not available in this build"})).await;
                        }
                    }
                    kind=>{
                        let folder=kind=="folder";
                        let resource=payload["resource"].as_str().filter(|id|id.len()<=128).ok_or(AccessError::InvalidSpec)?.to_string();
                        self.tasks.spawn(async move{let result=if folder{engine.serve_folder(&id,revision,peer,&resource,sid,mux.clone(),host).await}else{engine.serve_forward(&id,revision,peer,&resource,sid,mux.clone(),host.now_secs()).await};if let Err(error)=result{let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;}});
                    }
                }
            },
            _=>return Err(AccessError::Unsupported),
        }Ok(false)
    }
}
fn signature(value:&Value)->Result<[u8;64],AccessError>{let raw=value["signature"].as_str().filter(|s|s.len()==128).ok_or(AccessError::InvalidProof)?;hex::decode(raw).map_err(|_|AccessError::InvalidProof)?.try_into().map_err(|_|AccessError::InvalidProof)}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{ServiceAccess,ServiceProtocol};
    use crate::host::NoHost;
    use crate::send::ceremony::Inbound;
    struct Fixture(std::path::PathBuf);
    impl Fixture{fn new()->Self{let mut r=[0;16];getrandom::getrandom(&mut r).unwrap();let root=std::env::temp_dir().join(format!("access-session-{}",hex::encode(r)));std::fs::create_dir(&root).unwrap();Self(root)}}
    impl Drop for Fixture{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    struct Port(mpsc::Sender<AccessInbound>);
    #[async_trait::async_trait]
    impl filament_transport::net::Transport for Port{
        async fn send_control(&self,v:&Value)->anyhow::Result<()>{self.0.send(AccessInbound::Control(v.clone())).await.map_err(|_|anyhow::anyhow!("peer closed"))}
        async fn send_frame(&self,sid:u32,_:u64,data:&[u8])->anyhow::Result<()>{self.0.send(AccessInbound::Frame{sid,data:Bytes::copy_from_slice(data)}).await.map_err(|_|anyhow::anyhow!("peer closed"))}
        async fn flush(&self)->anyhow::Result<()>{Ok(())}
        fn max_payload(&self)->usize{65536}fn is_dead(&self)->bool{false}fn is_alive(&self)->bool{true}fn as_any(&self)->&dyn std::any::Any{self}
    }
    #[derive(Default)]
    struct Host{delegated:bool}
    #[async_trait::async_trait]
    impl HostServices for Host{
        fn now_secs(&self)->u64{10}
        fn settings_get_str(&self,k:&str)->Option<String>{NoHost.settings_get_str(k)}
        fn devices_load(&self)->Vec<(String,String)>{vec![]}
        fn is_self_uid(&self,a:&str,b:Option<&str>)->bool{NoHost.is_self_uid(a,b)}
        fn rejoin_unwarned(&self)->Duration{NoHost.rejoin_unwarned()}
        fn relay_banner(&self)->String{String::new()}fn relay_forbidden(&self)->bool{false}
        fn channel_of(&self,s:&str)->String{NoHost.channel_of(s)}fn roster_snapshot_json(&self)->Option<String>{None}fn fleet_rv_present(&self)->bool{false}
        fn delegated_access_for(&self,_:&[u8;32])->Option<crate::host::DelegatedAccess>{self.delegated.then(||crate::host::DelegatedAccess{ceiling:vec!["transfer".into()],deadline:u64::MAX})}
        async fn connect_local_stream(&self,h:&str,p:u16)->std::io::Result<tokio::net::TcpStream>{tokio::net::TcpStream::connect((h,p)).await}
    }
    fn pair(spec:AccessSpec)->(Fixture,AccessDispatch,AccessHandle,AccessDispatch,AccessHandle){
        pair_with(spec,None)
    }
    fn pair_with(spec:AccessSpec,shell:Option<ShellRuntime>)->(Fixture,AccessDispatch,AccessHandle,AccessDispatch,AccessHandle){
        let fixture=Fixture::new();let hostkey=OverlayKey::new(fixture.0.join("host.ed25519"));let recipientkey=OverlayKey::new(fixture.0.join("recipient.ed25519"));
        let hostpub=hostkey.public_key_bytes().unwrap();let _=recipientkey.public_key_bytes().unwrap();
        let binding=TemporaryBinding::new(hostpub,&spec,Lifetime::UntilEnded,50).unwrap();
        let mut host=Ceremony::new_temporary("session fixture words","1234",binding.clone(),TemporaryRole::Host);
        let mut recipient=Ceremony::new_temporary("session fixture words","1234",binding.clone(),TemporaryRole::Recipient);
        let hm=host.msg_payload();let rm=recipient.msg_payload();host.on_signal(&rm,None);recipient.on_signal(&hm,None);
        let hc=host.take_confirm_payload("host-fp","recipient-fp").unwrap();let rc=recipient.take_confirm_payload("recipient-fp","host-fp").unwrap();
        assert!(matches!(host.on_signal(&rc,Some(("host-fp","recipient-fp"))),Inbound::Consumed));
        assert!(matches!(recipient.on_signal(&hc,Some(("recipient-fp","host-fp"))),Inbound::Consumed));
        assert!(host.confirmed_temporary_transport("host-fp","recipient-fp"));assert!(!host.confirmed_temporary_transport("recipient-fp","host-fp"));
        let (htx,hrx)=access_channel();let(rtx,rrx)=access_channel();
        // Test-only construction inside this module; production has only the
        // sealed from_conn constructor, which checks the actual DTLS link.
        let host_connection=AuthenticatedAccessConnection{ceremony:host,transport:Arc::new(Port(rtx)),incoming:hrx};
        let recipient_connection=AuthenticatedAccessConnection{ceremony:recipient,transport:Arc::new(Port(htx)),incoming:rrx};
        let draft=AccessOfferDraft{binding,spec,lifetime:Lifetime::UntilEnded,claim_expires_at:50,label:"existing-device".into()};
        let(host,hh)=AccessDispatch::new_with_shell(host_connection,hostkey,Arc::new(Host::default()),Some(draft),vec![],shell).unwrap();
        let(recipient,rh)=AccessDispatch::new(recipient_connection,recipientkey,Arc::new(NoHost),None,vec![]).unwrap();
        (fixture,host,hh,recipient,rh)
    }
    async fn phase(handle:&AccessHandle,phase:AccessPhase){tokio::time::timeout(Duration::from_secs(3),async{loop{let view=handle.snapshot().unwrap();if view.phase==phase{return;}assert!(view.phase!=AccessPhase::Failed,"{:?}",view.failure);tokio::task::yield_now().await;}}).await.unwrap();}

    #[test]
    fn observations_are_bounded_and_handles_do_not_invent_contact_state(){
        let(fixture,_host,handle,_recipient,_other)=pair(AccessSpec::default());
        let observer=handle.observer();for _ in 0..140{observer.publish(AccessView{phase:AccessPhase::Review,agreement:None,peer_acknowledged_end:false,failure:None});}
        let events=observer.events(0).unwrap();assert!(events.reset_required);assert_eq!(events.events.len(),128);assert!(!observer.events(events.latest).unwrap().reset_required);
        assert!(!fixture.0.join("devices.json").exists());assert!(!fixture.0.join("caps.json").exists());
    }

    #[tokio::test]
    async fn known_delegated_peer_cannot_use_temporary_proof_to_bypass_signed_ceiling(){
        let(_fixture,mut host,hh,recipient,rh)=pair(AccessSpec::default());host.host=Arc::new(Host{delegated:true});
        let ht=tokio::spawn(host.drive(Cancellation::default()));let rt=tokio::spawn(recipient.drive(Cancellation::default()));
        assert_eq!(tokio::time::timeout(Duration::from_secs(3),ht).await.unwrap().unwrap(),Err(AccessError::Unsupported));
        let _=tokio::time::timeout(Duration::from_secs(3),rt).await.unwrap().unwrap();assert!(hh.snapshot().unwrap().agreement.is_none());assert_ne!(rh.snapshot().unwrap().phase,AccessPhase::Active);
    }

    #[cfg(feature="forward-server")]
    #[tokio::test]
    async fn real_control_proof_accept_and_tcp_end_is_owned_and_never_creates_contacts(){
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let spec=AccessSpec{services:vec![ServiceAccess{id:"echo".into(),target:listener.local_addr().unwrap(),protocol:ServiceProtocol::Tcp}],..AccessSpec::default()};
        let(fixture,host,hh,recipient,rh)=pair(spec);
        let stop=Cancellation::default();let hosttask=tokio::spawn(host.drive(stop.clone()));let recipienttask=tokio::spawn(recipient.drive(Cancellation::default()));
        phase(&rh,AccessPhase::Review).await;assert_eq!(hh.snapshot().unwrap().agreement.unwrap().state,AgreementState::Offered);
        let accepted=rh.accept(1).await.unwrap();assert_eq!(accepted.state,AgreementState::Active);
        let mut pipe=rh.open_service(1,"echo".into()).await.unwrap();let(mut socket,_)=listener.accept().await.unwrap();
        pipe.transport.send_frame(pipe.sid,0,b"real tcp").await.unwrap();let mut bytes=[0;8];socket.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"real tcp");
        socket.write_all(b"reply").await.unwrap();let response=pipe.stream.as_mut().unwrap().recv().await.unwrap().unwrap();assert_eq!(&response[..],b"reply");
        assert_eq!(hh.end().await.unwrap().state,AgreementState::Ended);assert_eq!(hh.end().await.unwrap().state,AgreementState::Ended);
        assert_eq!(socket.read(&mut bytes).await.unwrap(),0);
        let _=tokio::time::timeout(Duration::from_secs(3),hosttask).await.unwrap().unwrap();let _=tokio::time::timeout(Duration::from_secs(3),recipienttask).await.unwrap().unwrap();
        assert_eq!(rh.snapshot().unwrap().phase,AccessPhase::Ended);
        assert!(!fixture.0.join("devices.json").exists());assert!(!fixture.0.join("caps.json").exists());
    }

    #[tokio::test]
    async fn dropping_handle_or_core_stop_ends_the_same_engine_without_accepting(){
        let(_fixture,host,hh,recipient,rh)=pair(AccessSpec::default());let observer=hh.observer();
        let hosttask=tokio::spawn(host.drive(Cancellation::default()));let recipienttask=tokio::spawn(recipient.drive(Cancellation::default()));
        phase(&rh,AccessPhase::Review).await;drop(hh);
        let _=tokio::time::timeout(Duration::from_secs(3),hosttask).await.unwrap().unwrap();let _=tokio::time::timeout(Duration::from_secs(3),recipienttask).await.unwrap().unwrap();
        assert_eq!(observer.snapshot().unwrap().agreement.unwrap().state,AgreementState::Ended);
        let(_fixture,host,_hh,recipient,rh)=pair(AccessSpec::default());let stop=Cancellation::default();let hosttask=tokio::spawn(host.drive(stop.clone()));let recipienttask=tokio::spawn(recipient.drive(Cancellation::default()));
        phase(&rh,AccessPhase::Review).await;stop.cancel();let _=tokio::time::timeout(Duration::from_secs(3),hosttask).await.unwrap().unwrap();let _=tokio::time::timeout(Duration::from_secs(3),recipienttask).await.unwrap().unwrap();assert_ne!(rh.snapshot().unwrap().agreement.unwrap().state,AgreementState::Active);
    }

    #[cfg(all(feature="mount-server",target_os="linux"))]
    #[tokio::test]
    async fn public_handle_folder_pipe_uses_real_protocol_bytes_and_revokes(){
        use crate::access::{FolderAccess,FolderMode};use crate::mount_proto::{MountClient,MountOp,MountResult,path_encode};
        let folder=Fixture::new();let expected:Vec<u8>=(0..65549).map(|n|(n%256)as u8).collect();std::fs::write(folder.0.join("file"),&expected).unwrap();
        let spec=AccessSpec{folders:vec![FolderAccess::canonical("docs".into(),&folder.0,FolderMode::ReadOnly).unwrap()],..AccessSpec::default()};
        let(_fixture,host,hh,recipient,rh)=pair(spec);let ht=tokio::spawn(host.drive(Cancellation::default()));let rt=tokio::spawn(recipient.drive(Cancellation::default()));
        phase(&rh,AccessPhase::Review).await;rh.accept(1).await.unwrap();
        let mut pipe=rh.open_folder(1,"docs".into()).await.unwrap();
        let mut client=MountClient::from_mux_v2_with_mode(pipe.transport.clone(),pipe.sid,pipe.stream.take().unwrap(),pipe.folder_caps.take().unwrap(),FolderMode::ReadOnly);
        let opened=client.call(MountOp::Open{path:path_encode(std::path::Path::new("file")),flags:libc::O_RDONLY}).await.unwrap();let MountResult::Ok(opened)=opened.result else{panic!("open failed")};let fh=opened["fh"].as_u64().unwrap();
        let mut bytes=Vec::new();let cancel=Cancellation::default();loop{let read=client.read_binary(fh,bytes.len()as u64,32768,Duration::from_secs(2),&cancel).await.unwrap();if read.is_empty(){break;}bytes.extend_from_slice(&read);}assert_eq!(bytes,expected);
        hh.end().await.unwrap();let _=ht.await.unwrap();let _=rt.await.unwrap();assert!(client.read_binary(fh,0,1,Duration::from_secs(2),&cancel).await.is_err());
    }

    #[cfg(all(unix, feature="exec-server"))]
    mod shell_contract {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context,Poll};
        use tokio::io::{AsyncRead,ReadBuf};
        use crate::shell::exec::{ExecChild,ExecExit,ExecProcess,ExecSpawnSpec,ExecUserContext};

        struct BytesReader{bytes:Vec<u8>,at:usize}
        impl AsyncRead for BytesReader{
            fn poll_read(mut self:Pin<&mut Self>,_:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<std::io::Result<()>>{
                if self.at>=self.bytes.len(){return Poll::Ready(Ok(()));}
                let n=(self.bytes.len()-self.at).min(buf.remaining());let start=self.at;
                buf.put_slice(&self.bytes[start..start+n]);self.at+=n;Poll::Ready(Ok(()))
            }
        }
        /// Lives until the agreement tears it down, so stdin/control paths are
        /// observable instead of racing an immediate exit.
        struct ShellChild{stdin:Option<Box<dyn tokio::io::AsyncWrite+Unpin+Send>>,stdout:Option<Box<dyn AsyncRead+Unpin+Send>>,stderr:Option<Box<dyn AsyncRead+Unpin+Send>>}
        #[async_trait::async_trait]
        impl ExecChild for ShellChild{
            fn take_stdin(&mut self)->Option<Box<dyn tokio::io::AsyncWrite+Unpin+Send>>{self.stdin.take()}
            fn take_stdout(&mut self)->Option<Box<dyn AsyncRead+Unpin+Send>>{self.stdout.take()}
            fn take_stderr(&mut self)->Option<Box<dyn AsyncRead+Unpin+Send>>{self.stderr.take()}
            async fn wait(&mut self)->std::io::Result<ExecExit>{std::future::pending::<()>().await;unreachable!()}
            fn try_wait(&mut self)->std::io::Result<Option<ExecExit>>{Ok(None)}
            fn start_kill(&mut self){}
            fn signal_group(&self,_:crate::l2::mux::TreeSignal)->bool{true}
            fn group_alive(&self)->bool{true}
        }
        /// Records the exact spawn request the existing server builds; the
        /// wrapper must never switch accounts, so `user_drop_argv` is a panic.
        struct ShellProcess{spawned:Arc<Mutex<Option<ExecSpawnSpec>>>}
        impl ExecProcess for ShellProcess{
            fn resolve_program(&self,program:&str)->Option<std::path::PathBuf>{Some(std::path::PathBuf::from(program))}
            fn daemon_environment(&self)->Vec<(String,String)>{vec![("TERM".into(),"xterm".into()),("SECRET".into(),"nope".into())]}
            fn user_context(&self,_:Option<&str>)->Result<ExecUserContext,String>{Err("the standard-account wrapper must own the identity".into())}
            fn user_drop_argv(&self,_:&std::path::Path,_:&[String],_:&str)->Result<Vec<String>,String>{panic!("temporary shell must never perform an account switch")}
            fn spawn(&self,spec:ExecSpawnSpec)->Result<Box<dyn ExecChild>,String>{
                *self.spawned.lock().unwrap()=Some(spec);
                Ok(Box::new(ShellChild{stdin:Some(Box::new(tokio::io::sink())),stdout:Some(Box::new(BytesReader{bytes:b"shell output\n".to_vec(),at:0})),stderr:Some(Box::new(BytesReader{bytes:b"shell stderr\n".to_vec(),at:0}))}))
            }
        }

        #[tokio::test]
        async fn shell_open_uses_the_accepted_agreement_standard_account_and_end_tears_down(){
            if unsafe{libc::geteuid()}==0{return;}
            let process=Arc::new(ShellProcess{spawned:Arc::new(Mutex::new(None))});
            let runtime=ShellRuntime::new(process.clone(),Arc::new(crate::host::NoLog));
            let spec=AccessSpec{shell:true,..AccessSpec::default()};
            let(_fixture,host,hh,recipient,rh)=pair_with(spec,Some(runtime));
            let ht=tokio::spawn(host.drive(Cancellation::default()));let rt=tokio::spawn(recipient.drive(Cancellation::default()));
            phase(&rh,AccessPhase::Review).await;
            let early=rh.open_shell(1,ShellRequest{argv:vec!["/bin/echo".into()],cwd:None,env:vec![],alive_ms:None}).await;
            assert_eq!(early.err(),Some(AccessError::NotAccepted),"acceptance is not a caller flag");
            rh.accept(1).await.unwrap();
            let mut shell=rh.open_shell(1,ShellRequest{argv:vec!["/bin/echo".into(),"hello world".into()],cwd:None,env:vec![("FOO".into(),"bar".into())],alive_ms:None}).await.unwrap();
            let stdout=tokio::time::timeout(Duration::from_secs(3),shell.stdout.as_mut().unwrap().recv()).await.unwrap().unwrap().unwrap();
            assert_eq!(&stdout[..],b"shell output\n");
            let stderr=tokio::time::timeout(Duration::from_secs(3),shell.stderr.as_mut().unwrap().recv()).await.unwrap().unwrap().unwrap();
            assert_eq!(&stderr[..],b"shell stderr\n");
            shell.write(b"typed input").await.unwrap();
            shell.alive().await.unwrap();
            let spawned=loop{if let Some(spec)=process.spawned.lock().unwrap().clone(){break spec;}tokio::task::yield_now().await;};
            assert_eq!(spawned.program,std::path::PathBuf::from("/bin/echo"));
            assert_eq!(spawned.args,vec!["hello world".to_string()],"argv is spawned exactly");
            assert_eq!(spawned.env.iter().find(|(k,_)|k=="FOO").map(|(_,v)|v.as_str()),Some("bar"));
            assert!(!spawned.env.iter().any(|(k,_)|k=="SECRET"),"the daemon environment is filtered");
            assert_eq!(hh.end().await.unwrap().state,AgreementState::Ended);
            let _=tokio::time::timeout(Duration::from_secs(3),ht).await.unwrap().unwrap();
            let _=tokio::time::timeout(Duration::from_secs(3),rt).await.unwrap().unwrap();
            let closed=tokio::time::timeout(Duration::from_secs(3),async{loop{match shell.stdout.as_mut().unwrap().recv().await{None|Some(None)=>return,Some(Some(_))=>panic!("unexpected bytes after end")}}}).await;
            assert!(closed.is_ok(),"end closes the shell stream");
            assert_eq!(rh.snapshot().unwrap().phase,AccessPhase::Ended);
        }
    }
}
