//! Owned download output, separate from transfer policy and OS mount readiness.
//! Linux reuses the existing private/exclusive receiver staging primitive, pins
//! the caller-selected directory, and publishes the OPEN file descriptor with
//! atomic no-clobber linkat. No unique_path+rename overwrite race is used.
use std::path::{Path,PathBuf};
use crate::driver::Cancellation;
#[derive(Debug)]
pub enum OutputError { Unsupported,InvalidName,Limit,SizeMismatch,DigestMismatch,Cancelled,Failed,Io(std::io::ErrorKind),DurabilityUnknown(PathBuf) }
impl std::fmt::Display for OutputError{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"download output: {self:?}")}}
impl std::error::Error for OutputError{}
impl From<std::io::Error> for OutputError{fn from(e:std::io::Error)->Self{Self::Io(e.kind())}}
#[derive(Debug)]
pub struct PublishedDownload { pub path:PathBuf,pub bytes:u64,pub sha256:[u8;32] }
pub struct OwnedDownload {
    #[cfg(all(target_os="linux",feature="mount-server"))] file:tokio::fs::File,
    #[cfg(all(target_os="linux",feature="mount-server"))] directory:std::fs::File,
    #[cfg(all(target_os="linux",feature="mount-server"))] staging:std::ffi::CString,
    #[cfg(all(target_os="linux",feature="mount-server"))] name:String,
    #[cfg(all(target_os="linux",feature="mount-server"))] expected:u64,
    #[cfg(all(target_os="linux",feature="mount-server"))] written:u64,
    #[cfg(all(target_os="linux",feature="mount-server"))] digest:ring::digest::Context,
    #[cfg(all(target_os="linux",feature="mount-server"))] expected_digest:Option<[u8;32]>,
    #[cfg(all(target_os="linux",feature="mount-server"))] failed:bool,
}
impl OwnedDownload {
    /// `directory` and `name` are caller-selected destination facts, not a peer
    /// absolute path. Admission quota is explicit per call, never ambient env.
    pub async fn create(directory:&Path,name:&str,expected_bytes:u64,max_bytes:u64,expected_digest:Option<[u8;32]>)->Result<Self,OutputError>{
        #[cfg(not(all(target_os="linux",feature="mount-server")))]
        {let _=(directory,name,expected_bytes,max_bytes,expected_digest);Err(OutputError::Unsupported)}
        #[cfg(all(target_os="linux",feature="mount-server"))]
        {
            use std::os::fd::AsRawFd;use std::os::unix::fs::OpenOptionsExt;
            if name.is_empty()||name.len()>128||name=="."||name==".."||name.bytes().any(|b|matches!(b,b'/'|b'\\'|0)){return Err(OutputError::InvalidName);}
            if expected_bytes>max_bytes{return Err(OutputError::Limit);}
            let canonical=directory.canonicalize()?;
            let directory=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(canonical)?;
            let pinned=PathBuf::from(format!("/proc/self/fd/{}",directory.as_raw_fd()));
            if !pinned.is_dir(){return Err(OutputError::Unsupported);}
            for _ in 0..16{
                let mut random=[0;16];getrandom::getrandom(&mut random).map_err(|_|OutputError::Failed)?;
                let staging=format!(".tunlion-download-{}.part",hex::encode(random));
                match crate::recv::safe_create_part(&pinned.join(&staging)).await{
                    Ok(file)=>return Ok(Self{file,directory,staging:std::ffi::CString::new(staging).map_err(|_|OutputError::InvalidName)?,name:name.into(),expected:expected_bytes,written:0,digest:ring::digest::Context::new(&ring::digest::SHA256),expected_digest,failed:false}),
                    Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>continue,
                    Err(e)=>return Err(e.into()),
                }
            }Err(OutputError::Limit)
        }
    }
    pub async fn write_chunk(&mut self,bytes:&[u8],cancel:&Cancellation)->Result<(),OutputError>{
        #[cfg(not(all(target_os="linux",feature="mount-server")))]
        {let _=(bytes,cancel);Err(OutputError::Unsupported)}
        #[cfg(all(target_os="linux",feature="mount-server"))]
        {
            use tokio::io::AsyncWriteExt;
            if self.failed{return Err(OutputError::Failed);}
            let next=self.written.checked_add(bytes.len()as u64).filter(|n|*n<=self.expected).ok_or(OutputError::Limit);
            let next=match next{Ok(n)=>n,Err(e)=>{self.failed=true;return Err(e);}};
            match cancel.run(self.file.write_all(bytes)).await{
                crate::driver::DriverOutcome::Cancelled=>{self.failed=true;Err(OutputError::Cancelled)},
                crate::driver::DriverOutcome::Returned(Err(e))=>{self.failed=true;Err(e.into())},
                crate::driver::DriverOutcome::Returned(Ok(()))=>{self.written=next;self.digest.update(bytes);Ok(())},
            }
        }
    }
    /// Cancellation is checked after file fsync and immediately before the
    /// atomic publication commit. Cancellation AFTER commit cannot undo copied
    /// data. The final no-await section links/unlinks/fsyncs the pinned directory;
    /// a directory fsync failure is explicitly durability-unknown, not success.
    pub async fn finish(mut self,cancel:&Cancellation)->Result<PublishedDownload,OutputError>{
        #[cfg(not(all(target_os="linux",feature="mount-server")))]
        {let _=cancel;Err(OutputError::Unsupported)}
        #[cfg(all(target_os="linux",feature="mount-server"))]
        {
            use std::os::fd::AsRawFd;use tokio::io::AsyncWriteExt;
            if self.failed{return Err(OutputError::Failed);}if self.written!=self.expected{return Err(OutputError::SizeMismatch);}
            let digest:[u8;32]=self.digest.clone().finish().as_ref().try_into().map_err(|_|OutputError::Failed)?;
            if self.expected_digest.is_some_and(|expected|expected!=digest){return Err(OutputError::DigestMismatch);}
            match cancel.run(async{self.file.flush().await?;self.file.sync_all().await}).await{
                crate::driver::DriverOutcome::Cancelled=>return Err(OutputError::Cancelled),
                crate::driver::DriverOutcome::Returned(result)=>result?,
            }
            if cancel.is_cancelled(){return Err(OutputError::Cancelled);}
            let root=std::fs::read_link(format!("/proc/self/fd/{}",self.directory.as_raw_fd()))?;
            let source=std::ffi::CString::new(format!("/proc/self/fd/{}",self.file.as_raw_fd())).map_err(|_|OutputError::Failed)?;
            for suffix in 0..1024u32{
                let candidate=if suffix==0{self.name.clone()}else{format!("{}-{suffix}",self.name)};
                let target=std::ffi::CString::new(candidate.clone()).map_err(|_|OutputError::InvalidName)?;
                // Link the pinned OPEN inode, not a replaceable staging name.
                let rc=unsafe{libc::linkat(libc::AT_FDCWD,source.as_ptr(),self.directory.as_raw_fd(),target.as_ptr(),libc::AT_SYMLINK_FOLLOW)};
                if rc==0{
                    let path=root.join(candidate);
                    unsafe{libc::unlinkat(self.directory.as_raw_fd(),self.staging.as_ptr(),0);}
                    self.directory.sync_all().map_err(|_|OutputError::DurabilityUnknown(path.clone()))?;
                    return Ok(PublishedDownload{path,bytes:self.written,sha256:digest});
                }
                let error=std::io::Error::last_os_error();if error.kind()==std::io::ErrorKind::AlreadyExists{continue;}return Err(error.into());
            }Err(OutputError::Limit)
        }
    }
}
impl Drop for OwnedDownload{fn drop(&mut self){#[cfg(all(target_os="linux",feature="mount-server"))]{use std::os::fd::AsRawFd;unsafe{libc::unlinkat(self.directory.as_raw_fd(),self.staging.as_ptr(),0);}}}}

#[cfg(all(test,target_os="linux",feature="mount-server"))]
mod tests{
    use super::*;
    struct Root(PathBuf);impl Root{fn new()->Self{let mut r=[0;16];getrandom::getrandom(&mut r).unwrap();let path=std::env::temp_dir().join(format!("download-output-{}",hex::encode(r)));std::fs::create_dir(&path).unwrap();Self(path)}}impl Drop for Root{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    #[tokio::test]
    async fn exact_binary_empty_and_existing_names_publish_without_overwrite(){
        use std::os::unix::fs::PermissionsExt;
        let root=Root::new();std::fs::write(root.0.join("file"),b"existing").unwrap();
        let bytes:Vec<_>=(0..65549).map(|n|(n%256)as u8).collect();let digest=ring::digest::digest(&ring::digest::SHA256,&bytes);let expected=digest.as_ref().try_into().unwrap();let cancel=Cancellation::default();
        let mut output=OwnedDownload::create(&root.0,"file",bytes.len()as u64,100000,Some(expected)).await.unwrap();
        assert_eq!(output.file.metadata().await.unwrap().permissions().mode()&0o777,0o600);
        for chunk in bytes.chunks(32768){output.write_chunk(chunk,&cancel).await.unwrap();}
        let published=output.finish(&cancel).await.unwrap();assert_eq!(published.path,root.0.join("file-1"));assert_eq!(published.sha256,expected);assert_eq!(std::fs::read(published.path).unwrap(),bytes);assert_eq!(std::fs::read(root.0.join("file")).unwrap(),b"existing");
        let empty=OwnedDownload::create(&root.0,"empty",0,0,None).await.unwrap().finish(&cancel).await.unwrap();assert_eq!(std::fs::metadata(empty.path).unwrap().len(),0);
    }
    #[tokio::test]
    async fn cancel_size_digest_error_and_drop_remove_private_parts(){
        let root=Root::new();let cancel=Cancellation::default();
        let mut output=OwnedDownload::create(&root.0,"cancelled",3,3,None).await.unwrap();output.write_chunk(b"abc",&cancel).await.unwrap();cancel.cancel();assert!(matches!(output.finish(&cancel).await,Err(OutputError::Cancelled)));
        let live=Cancellation::default();let output=OwnedDownload::create(&root.0,"short",1,1,None).await.unwrap();assert!(matches!(output.finish(&live).await,Err(OutputError::SizeMismatch)));
        let mut output=OwnedDownload::create(&root.0,"digest",1,1,Some([0;32])).await.unwrap();output.write_chunk(b"x",&live).await.unwrap();assert!(matches!(output.finish(&live).await,Err(OutputError::DigestMismatch)));
        drop(OwnedDownload::create(&root.0,"dropped",0,0,None).await.unwrap());assert_eq!(std::fs::read_dir(&root.0).unwrap().count(),0);
        assert!(matches!(OwnedDownload::create(&root.0,"../escape",1,1,None).await,Err(OutputError::InvalidName)));
    }
    #[tokio::test]
    async fn pinned_root_survives_directory_substitution_without_writing_replacement(){
        let root=Root::new();let destination=root.0.join("dest");std::fs::create_dir(&destination).unwrap();let cancel=Cancellation::default();
        let mut output=OwnedDownload::create(&destination,"file",4,4,None).await.unwrap();output.write_chunk(b"safe",&cancel).await.unwrap();
        let moved=root.0.join("moved");std::fs::rename(&destination,&moved).unwrap();let replacement=root.0.join("replacement");std::fs::create_dir(&replacement).unwrap();std::os::unix::fs::symlink(&replacement,&destination).unwrap();
        let published=output.finish(&cancel).await.unwrap();assert_eq!(published.path,moved.join("file"));assert_eq!(std::fs::read(published.path).unwrap(),b"safe");assert_eq!(std::fs::read_dir(&replacement).unwrap().count(),0);
    }
    #[tokio::test]
    async fn open_inode_staging_substitution_never_publishes_attacker_content(){
        let root=Root::new();let destination=root.0.join("dest");std::fs::create_dir(&destination).unwrap();let cancel=Cancellation::default();
        let mut output=OwnedDownload::create(&destination,"file",4,4,None).await.unwrap();output.write_chunk(b"safe",&cancel).await.unwrap();
        let staging=destination.join(output.staging.to_str().unwrap());std::fs::remove_file(&staging).unwrap();std::fs::write(&staging,b"substituted").unwrap();
        // Linux may refuse to relink a completely unlinked inode through /proc.
        // Such a
        // substitution must either publish the original or fail, never publish
        // attacker bytes. The ordinary directory substitution remains supported.
        let moved=root.0.join("moved");std::fs::rename(&destination,&moved).unwrap();std::fs::create_dir(&destination).unwrap();
        match output.finish(&cancel).await{Ok(published)=>assert_eq!(std::fs::read(published.path).unwrap(),b"safe"),Err(OutputError::Io(_))=>{},other=>panic!("{other:?}")}
        assert!(!destination.join("file").exists());assert!(!moved.join("file").exists()||std::fs::read(moved.join("file")).unwrap()==b"safe");
    }
    #[tokio::test]
    async fn simultaneous_publishers_and_existing_symlink_never_clobber(){
        let root=Root::new();let cancel=Cancellation::default();
        let mut first=OwnedDownload::create(&root.0,"file",1,1,None).await.unwrap();let mut second=OwnedDownload::create(&root.0,"file",1,1,None).await.unwrap();first.write_chunk(b"a",&cancel).await.unwrap();second.write_chunk(b"b",&cancel).await.unwrap();
        std::fs::write(root.0.join("original"),b"preserve").unwrap();std::os::unix::fs::symlink(root.0.join("original"),root.0.join("file")).unwrap();
        let (first,second)=tokio::join!(first.finish(&cancel),second.finish(&cancel));let first=first.unwrap();let second=second.unwrap();assert_ne!(first.path,second.path);assert_eq!(std::fs::read(first.path).unwrap(),b"a");assert_eq!(std::fs::read(second.path).unwrap(),b"b");assert_eq!(std::fs::read(root.0.join("original")).unwrap(),b"preserve");assert!(std::fs::symlink_metadata(root.0.join("file")).unwrap().file_type().is_symlink());
    }
}
