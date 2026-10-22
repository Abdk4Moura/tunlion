//! Restrictive process MECHANISM seam, not shell permission/admission. Resolve
//! the existing local OS account without environment/name/role assertions and
//! refuse privileged daemon identity. Agreement-aware exec/PTy/SSH serving and
//! authoritative primary consent remain separate, unavailable integration work.
use std::path::{Path,PathBuf};
use std::sync::Arc;
use super::exec::{ExecChild,ExecProcess,ExecSpawnSpec,ExecUserContext};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ShellAccountError { Unsupported,PrivilegedService,IdentityChanged,Unavailable }
impl std::fmt::Display for ShellAccountError{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"standard local account: {self:?}")}}
impl std::error::Error for ShellAccountError{}

/// The resolved local login identity, revalidated immediately before a spawn.
///
/// This is the account half of [`StandardLocalExecProcess`], shared with the
/// PTY seam: both refuse a root/service identity and a real/effective UID
/// mismatch, and neither performs account switching. The value is the OS
/// password-database record for this process, never an environment label.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct StandardLocalAccount(ExecUserContext);
impl StandardLocalAccount {
    pub fn resolve()->Result<Self,ShellAccountError>{current_standard_account().map(Self)}
    /// Re-read the OS identity and refuse if it changed since `resolve`.
    pub fn revalidate(&self)->Result<(),ShellAccountError>{
        let current=current_standard_account()?;
        if current!=self.0{return Err(ShellAccountError::IdentityChanged);}Ok(())
    }
    pub fn context(&self)->&ExecUserContext{&self.0}
}

pub struct StandardLocalExecProcess { inner:Arc<dyn ExecProcess>,account:ExecUserContext }
impl StandardLocalExecProcess {
    pub fn new(inner:Arc<dyn ExecProcess>)->Result<Self,ShellAccountError>{
        let account=StandardLocalAccount::resolve()?.0;Ok(Self{inner,account})
    }
    pub fn account(&self)->&ExecUserContext{&self.account}
    fn revalidate(&self)->Result<ExecUserContext,ShellAccountError>{
        let current=current_standard_account()?;
        if current!=self.account{return Err(ShellAccountError::IdentityChanged);}Ok(current)
    }
}
impl ExecProcess for StandardLocalExecProcess {
    fn resolve_program(&self,program:&str)->Option<PathBuf>{self.inner.resolve_program(program)}
    fn daemon_environment(&self)->Vec<(String,String)>{self.inner.daemon_environment()}
    fn user_context(&self,user:Option<&str>)->Result<ExecUserContext,String>{
        if user.is_some(){return Err("standard local account backend does not perform account switching".into());}
        self.revalidate().map_err(|e|e.to_string())
    }
    fn user_drop_argv(&self,_:&Path,_:&[String],_:&str)->Result<Vec<String>,String>{Err("standard local account backend refuses account switching; no daemon fallback".into())}
    fn spawn(&self,spec:ExecSpawnSpec)->Result<Box<dyn ExecChild>,String>{
        // Last check immediately before entering the existing host spawn/fork
        // primitive. The primitive must honor ExecProcess's existing contract:
        // no extra account/token substitution or daemon environment injection.
        self.revalidate().map_err(|e|e.to_string())?;self.inner.spawn(spec)
    }
    fn test_expiry_close_first(&self)->bool{self.inner.test_expiry_close_first()}
}

fn same_standard_uid(real:u32,effective:u32)->Result<(),ShellAccountError>{
    if real==0||effective==0{return Err(ShellAccountError::PrivilegedService);}
    if real!=effective{return Err(ShellAccountError::IdentityChanged);}Ok(())
}
fn current_standard_account()->Result<ExecUserContext,ShellAccountError>{
    #[cfg(not(unix))]
    {Err(ShellAccountError::Unsupported)}
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let real=unsafe{libc::getuid()};let effective=unsafe{libc::geteuid()};same_standard_uid(real,effective)?;
        let hint=unsafe{libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX)};
        let mut size=if hint>0{(hint as usize).clamp(1024,1024*1024)}else{16384};
        loop{
            let mut buffer=vec![0u8;size];let mut record=std::mem::MaybeUninit::<libc::passwd>::uninit();let mut found=std::ptr::null_mut();
            let status=unsafe{libc::getpwuid_r(real,record.as_mut_ptr(),buffer.as_mut_ptr().cast(),buffer.len(),&mut found)};
            if status==libc::ERANGE&&size<1024*1024{size=(size*2).min(1024*1024);continue;}
            if status!=0||found.is_null(){return Err(ShellAccountError::Unavailable);}
            let record=unsafe{record.assume_init()};
            if record.pw_uid!=real||record.pw_name.is_null()||record.pw_dir.is_null(){return Err(ShellAccountError::Unavailable);}
            // getpwuid_r owns these NUL-terminated fields inside `buffer`; copy
            // all values before that buffer is released. Identity is the UID,
            // never an environment USER/USERNAME or caller-provided label.
            let name=unsafe{std::ffi::CStr::from_ptr(record.pw_name)}.to_str().map_err(|_|ShellAccountError::Unavailable)?.to_string();
            let home=PathBuf::from(std::ffi::OsString::from_vec(unsafe{std::ffi::CStr::from_ptr(record.pw_dir)}.to_bytes().to_vec()));
            let shell=if record.pw_shell.is_null(){None}else{Some(unsafe{std::ffi::CStr::from_ptr(record.pw_shell)}.to_str().map_err(|_|ShellAccountError::Unavailable)?.to_string())};
            if name.is_empty()||!home.is_absolute(){return Err(ShellAccountError::Unavailable);}
            same_standard_uid(unsafe{libc::getuid()},unsafe{libc::geteuid()})?;
            if unsafe{libc::getuid()}!=real{return Err(ShellAccountError::IdentityChanged);}
            return Ok(ExecUserContext{name,home,shell,uid:Some(real)});
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    struct Host;
    impl ExecProcess for Host{
        fn resolve_program(&self,p:&str)->Option<PathBuf>{Some(p.into())}
        fn daemon_environment(&self)->Vec<(String,String)>{vec![("USER".into(),"untrusted-daemon-label".into())]}
        fn user_context(&self,_:Option<&str>)->Result<ExecUserContext,String>{panic!("identity must come from OS, not host assertions")}
        fn user_drop_argv(&self,_:&Path,_:&[String],_:&str)->Result<Vec<String>,String>{panic!("no account-switching fallback")}
        fn spawn(&self,_:ExecSpawnSpec)->Result<Box<dyn ExecChild>,String>{Err("existing process primitive reached without account switching".into())}
    }
    #[test]
    fn privileged_and_mismatched_ids_fail_but_normal_admin_membership_is_not_guessed(){
        assert_eq!(same_standard_uid(0,0),Err(ShellAccountError::PrivilegedService));assert_eq!(same_standard_uid(1000,0),Err(ShellAccountError::PrivilegedService));assert_eq!(same_standard_uid(0,1000),Err(ShellAccountError::PrivilegedService));assert_eq!(same_standard_uid(1000,1001),Err(ShellAccountError::IdentityChanged));assert_eq!(same_standard_uid(1000,1000),Ok(()));
    }
    #[cfg(unix)]
    #[test]
    fn actual_existing_account_is_resolved_without_daemon_label_or_user_drop(){
        let real=unsafe{libc::getuid()};let effective=unsafe{libc::geteuid()};
        if real==0||effective==0{assert!(matches!(StandardLocalExecProcess::new(Arc::new(Host)),Err(ShellAccountError::PrivilegedService)));return;}
        if real!=effective{assert!(matches!(StandardLocalExecProcess::new(Arc::new(Host)),Err(ShellAccountError::IdentityChanged)));return;}
        let process=StandardLocalExecProcess::new(Arc::new(Host)).unwrap();assert_eq!(process.account().uid,Some(real));assert_ne!(process.account().name,"untrusted-daemon-label");assert_eq!(process.user_context(None).unwrap(),*process.account());assert!(process.user_context(Some("other")).is_err());assert!(process.user_drop_argv(Path::new("/bin/sh"),&[],"other").is_err());
        let account=StandardLocalAccount::resolve().unwrap();assert_eq!(account.context(),process.account());assert!(account.revalidate().is_ok());
        let spec=ExecSpawnSpec{program:"/bin/true".into(),args:vec![],cwd:process.account().home.clone(),env:vec![]};assert!(process.spawn(spec).err().unwrap().contains("existing process primitive"));
    }
    #[cfg(not(unix))]
    #[test]
    fn no_windows_service_token_fallback(){assert!(matches!(StandardLocalExecProcess::new(Arc::new(Host)),Err(ShellAccountError::Unsupported)));}
}
