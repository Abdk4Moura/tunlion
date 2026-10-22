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
enum Command { Accept(u64,Reply),Update(u64,AccessSpec,Lifetime,Reply),End(Reply),Open(u64,String,bool,OpenReply) }
/// Own this pipe for the entire operation. Dropping it closes only its own SID.
pub struct AccessPipe {
    pub sid:u32,pub transport:Arc<dyn filament_transport::net::Transport>,
    pub stream:Option<mpsc::Receiver<crate::l2::PipeItem>>,
    #[cfg(feature="mount-server")] pub folder_caps:Option<crate::mount_proto::MountCaps>,
    mux:Arc<Mux>,generation:u64,
}
impl Drop for AccessPipe{fn drop(&mut self){if let Ok(rt)=tokio::runtime::Handle::try_current(){let mux=self.mux.clone();let sid=self.sid;let generation=self.generation;rt.spawn(async move{mux.drop_stream_if(sid,generation).await;let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid})).await;});}}}
struct PendingOpen { reply:OpenReply,stream:mpsc::Receiver<crate::l2::PipeItem>,generation:u64,folder:bool }
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
}
impl AccessDispatch {
    pub fn new(connection:AuthenticatedAccessConnection,key:OverlayKey,host:Arc<dyn HostServices>,draft:Option<AccessOfferDraft>,names:Vec<String>)->Result<(Self,AccessHandle),AccessError>{
        let local=key.public_key_bytes().map_err(|_|AccessError::Unavailable)?;
        let binding=connection.ceremony.temporary_binding().ok_or(AccessError::InvalidProof)?;
        let role=connection.ceremony.temporary_role().ok_or(AccessError::InvalidProof)?;
        match (&draft,role){
            (Some(d),TemporaryRole::Host) if d.binding==*binding && binding.host_peer==local && d.binding.digest_for(&d.spec,d.lifetime,d.claim_expires_at)?==binding.offer_digest=>{},
            (None,TemporaryRole::Recipient) if binding.host_peer!=local=>{},
            _=>return Err(AccessError::InvalidProof),
        }
        let observer=AccessObserver(Arc::new(Mutex::new(Observed{view:AccessView{phase:AccessPhase::Authenticating,agreement:None,peer_acknowledged_end:false,failure:None},sequence:0,events:VecDeque::new()})));
        let (tx,commands)=mpsc::channel(8);let stop=Cancellation::default();
        let handle=AccessHandle(Arc::new(Client{tx,stop:stop.clone(),observer:observer.clone()}));
        let engine=draft.as_ref().map(|_|Arc::new(AgreementEngine::new(local,names)));
        let mux=Mux::new(connection.transport.clone(),host.clone());
        Ok((Self{connection,key,host,draft,commands,stop,observer,engine,peer:None,review:None,snapshot:None,mux,tasks:tokio::task::JoinSet::new(),ending:false,pending_accept:None,pending_opens:std::collections::BTreeMap::new()},handle))
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
                _=core_stop.run(std::future::pending::<()>())=>return Ok(()),
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
                    let abandoned:Vec<_>=self.pending_opens.iter().filter(|(_,open)|open.reply.is_closed()).map(|(sid,_)|*sid).collect();
                    for sid in abandoned{if let Some(open)=self.pending_opens.remove(&sid){self.mux.drop_stream_if(sid,open.generation).await;let _=self.send(json!({"type":"l2-close","sid":sid})).await;}}
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
    async fn control(&mut self,payload:Value)->Result<bool,AccessError>{
        if serde_json::to_vec(&payload).map_err(|_|AccessError::InvalidSpec)?.len()>128*1024{return Err(AccessError::Capacity);}
        let kind=payload["type"].as_str().ok_or(AccessError::InvalidSpec)?;
        if kind=="l2-close"{if let Some(sid)=crate::l2::wire_sid(&payload){self.mux.on_close(sid,payload["err"].as_str()).await;if let Some(open)=self.pending_opens.remove(&sid){let _=open.reply.send(Err(AccessError::Unavailable));}}return Ok(false);}
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
        if payload["v"].as_u64()!=Some(1){return Err(AccessError::Unsupported);}
        let local=self.key.public_key_bytes().map_err(|_|AccessError::Unavailable)?;
        if kind=="access-possession"{
            let peer=self.connection.ceremony.authenticate_temporary_payload(local,&payload)?;
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
            "access-end"=>{self.ending=true;self.cleanup().await;self.send(json!({"type":"access-end-ack","v":1,"id":payload["id"]})).await?;self.view(AccessPhase::Ended,true,None);return Ok(true);},
            "access-end-ack" if self.ending=>{self.view(AccessPhase::Ended,true,None);return Ok(true);},
            "access-accept" if self.engine.is_some() && !self.ending=>{
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
                let revision=payload["revision"].as_u64().ok_or(AccessError::InvalidSpec)?;let sid=crate::l2::wire_sid(&payload).ok_or(AccessError::InvalidSpec)?;
                let resource=payload["resource"].as_str().filter(|id|id.len()<=128).ok_or(AccessError::InvalidSpec)?.to_string();
                if self.tasks.len()>=crate::l2::MAX_STREAMS_PER_LINK{return Err(AccessError::Capacity);}
                let folder=payload["kind"].as_str()==Some("folder");let engine=self.engine.as_ref().ok_or(AccessError::Unsupported)?.clone();
                let id=current.id.clone();let mux=self.mux.clone();let host=self.host.clone();
                self.tasks.spawn(async move{let result=if folder{engine.serve_folder(&id,revision,peer,&resource,sid,mux.clone(),host).await}else{engine.serve_forward(&id,revision,peer,&resource,sid,mux.clone(),host.now_secs()).await};if let Err(error)=result{let _=mux.transport().send_control(&json!({"type":"l2-close","sid":sid,"err":error.to_string()})).await;}});
            },
            _=>return Err(AccessError::Unsupported),
        }Ok(false)
    }
}
fn signature(value:&Value)->Result<[u8;64],AccessError>{let raw=value["signature"].as_str().filter(|s|s.len()==128).ok_or(AccessError::InvalidProof)?;hex::decode(raw).map_err(|_|AccessError::InvalidProof)?.try_into().map_err(|_|AccessError::InvalidProof)}
