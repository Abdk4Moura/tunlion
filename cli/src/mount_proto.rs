//! CLI shim over `filament_peerloop::mount_proto`.
//!
//! The wire types, caps negotiation, framing, client and server moved into the
//! peer-loop crate with the mount-open endpoint. Every caller (`l2`, the mount
//! command and the FUSE/WinFsp adapters) already named `crate::mount_proto`, so
//! this file is only that name.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::mount_proto::*;

#[cfg(test)]
mod tests {
    /// Transfer resume: `safe_resume_part` must refuse to open a symlink. This
    /// stays in the CLI because it drives the CLI transfer path; the moved
    /// `safe_open_beneath` unit tests live with the server.
    #[cfg(unix)]
    #[tokio::test]
    async fn transfer_open_part_refuses_symlink() {
        let uid = format!(
            "{}-resume-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let tmp = std::env::temp_dir().join(format!("fil-xfer-{uid}"));
        std::fs::create_dir_all(&tmp).unwrap();

        // Create a regular .part file first
        let part_path = tmp.join("data.tar.part");
        std::fs::write(&part_path, b"partial data").unwrap();

        // Verify it opens normally for resume
        let result = crate::recv_files::safe_resume_part(&part_path).await;
        assert!(result.is_ok(), "regular file must open normally for resume");

        // Now replace with a symlink
        std::fs::remove_file(&part_path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &part_path).unwrap();

        // Must refuse
        let result = crate::recv_files::safe_resume_part(&part_path).await;
        assert!(result.is_err(), "must refuse to resume through a symlink");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
