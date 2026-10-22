//! Rust embedding access API over the same Core engine slot/lease and shared
//! transport driver. Standalone code registration/signaling is not yet exposed:
//! callers hand off an existing completed purpose-authenticated Conn, never a
//! label, raw self-asserted peer key or an in-process invitation lookup.
use super::{Core,CoreError,StartClaim};
use filament_peerloop::access::AccessError;
use filament_peerloop::access_session::AccessDispatch;
use filament_peerloop::recv::store::{DeviceStore,OverlayKey};

pub use filament_peerloop::access::{AccessSpec,AgreementSnapshot,FolderAccess,FolderMode,Lifetime,Relationship,ServiceAccess,ServiceProtocol};
pub use filament_peerloop::access_session::{access_channel,AccessHandle,AccessInbound,AccessObserver,AccessOfferDraft,AccessPhase,AccessPipe,AccessSessionEvent,AccessSessionEvents,AccessView,AuthenticatedAccessConnection};

#[derive(Debug,thiserror::Error)]
pub enum AccessApiError {
    #[error(transparent)] Core(#[from] CoreError),
    #[error(transparent)] Access(#[from] AccessError),
}

impl Core {
    /// Prepare authenticated scope material, NOT a claimable code. Uses the
    /// existing internal key store on mutation; read-only inspection never mints.
    pub fn prepare_access_offer(&self,spec:AccessSpec,lifetime:Lifetime,claim_expires_at:u64)->Result<AccessOfferDraft,AccessApiError>{
        spec.validate()?;
        validate_endpoints(&spec)?;
        let now=filament_id::now_secs();
        if claim_expires_at<=now || matches!(lifetime,Lifetime::ExpiresAt(at) if at<=now){return Err(AccessError::Expired.into());}
        let store=DeviceStore::open(&self.dir);
        store.ensure_identity_on_mutation().map_err(super::id_err)?;
        let key=OverlayKey::new(self.dir.join("overlay.ed25519"));
        let local=key.public_key_bytes().map_err(super::id_err)?;
        let binding=filament_peerloop::send::ceremony::TemporaryBinding::new(local,&spec,lifetime,claim_expires_at)?;
        let settings=super::host::CoreSettings::load(&self.dir).map_err(super::io_err)?;
        let label=settings.get("name").filter(|s|!s.trim().is_empty()).unwrap_or_else(||"device".into());
        Ok(AccessOfferDraft{binding,spec,lifetime,claim_expires_at,label})
    }

    pub fn offer_access(&self,draft:AccessOfferDraft,connection:AuthenticatedAccessConnection)->Result<AccessHandle,AccessApiError>{
        validate_endpoints(&draft.spec)?;
        self.begin_access(connection,Some(draft))
    }

    /// Join on an existing PAKE-confirmed transport. No permanent contact or
    /// certificate is installed, and this does not claim/normalize a code.
    pub fn join_access(&self,connection:AuthenticatedAccessConnection)->Result<AccessHandle,AccessApiError>{self.begin_access(connection,None)}

    pub fn access_snapshot(&self)->Result<Option<AccessView>,AccessApiError>{
        let observer=self.access_observer.lock().map_err(|_|AccessError::Poisoned)?.clone();
        observer.map(|observer|observer.snapshot()).transpose().map_err(Into::into)
    }
    pub fn access_events(&self,after:u64)->Result<AccessSessionEvents,AccessApiError>{
        let observer=self.access_observer.lock().map_err(|_|AccessError::Poisoned)?.clone().ok_or(AccessError::NotFound)?;
        Ok(observer.events(after)?)
    }

    fn begin_access(&self,connection:AuthenticatedAccessConnection,draft:Option<AccessOfferDraft>)->Result<AccessHandle,AccessApiError>{
        let mut claim=StartClaim::acquire(self)?;
        let (parts,lease)=self.prepare_send()?;
        let key=OverlayKey::new(self.dir.join("overlay.ed25519"));
        let names=parts.ports.host.devices_load().into_iter().map(|(name,_)|name).collect();
        let (dispatch,access)=AccessDispatch::new(connection,key,parts.ports.host,draft,names)?;
        let observer=access.observer();let generation=claim.generation();
        let (handle,engine,watch)=self.spawn_engine(move|stop,ready|async move{
            ready.publish(||{});
            dispatch.drive(stop).await.map_err(|e|e.to_string())
        })?;
        claim.install(engine)?;
        self.finish_start(handle,watch,lease)?;
        // Same lock as starts: an old invocation may not replace its successor's
        // observer if stop/restart won between readiness and publication.
        let _slot=self.engine.lock().map_err(|_|AccessError::Poisoned)?;
        if self.engine_generation()!=generation{return Err(CoreError::Cancelled.into());}
        *self.access_observer.lock().map_err(|_|AccessError::Poisoned)?=Some(observer);
        Ok(access)
    }
}

fn validate_endpoints(spec:&AccessSpec)->Result<(),AccessError>{
    if spec.shell || spec.device_network || spec.services.iter().any(|s|s.protocol!=ServiceProtocol::Tcp){return Err(AccessError::Unsupported);}
    if spec.folders.is_empty() && spec.services.is_empty(){return Err(AccessError::InvalidSpec);}
    if !cfg!(feature="access-endpoints"){return Err(AccessError::Unsupported);}
    if !spec.folders.is_empty() && !cfg!(target_os="linux"){return Err(AccessError::Unsupported);}
    Ok(())
}
