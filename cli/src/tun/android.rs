//! Android has no kernel TUN an app process can open (a `VpnService` hands the
//! app a ready file descriptor instead, which is phase 2 of
//! docs/android-app-spec.md). Until then every kernel call here refuses, so the
//! overlay always takes the userspace netstack path on Android.

use anyhow::{bail, Result};

const NO_KERNEL_TUN: &str = "Android has no kernel TUN for apps; tunlion uses the userspace overlay here";

/// Never constructed: `open` always refuses.
pub struct KernelTun {
    name: String,
}

impl KernelTun {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn open(_requested: &str, _cidr: &str, _mtu: u32) -> Result<KernelTun> {
        bail!(NO_KERNEL_TUN)
    }

    pub async fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        bail!(NO_KERNEL_TUN)
    }

    pub async fn send(&self, _packet: &[u8]) -> Result<usize> {
        bail!(NO_KERNEL_TUN)
    }
}

#[async_trait::async_trait]
impl crate::tun::TunDevice for KernelTun {
    fn name(&self) -> &str {
        KernelTun::name(self)
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        KernelTun::recv(self, buf).await
    }
    async fn send(&self, packet: &[u8]) -> Result<usize> {
        KernelTun::send(self, packet).await
    }
}

pub fn add_route(_cidr: &str, _dev: &str) -> Result<()> {
    bail!(NO_KERNEL_TUN)
}

pub fn del_route(_cidr: &str, _dev: &str) -> Result<()> {
    bail!(NO_KERNEL_TUN)
}

pub fn add_addr(_cidr: &str, _dev: &str) -> Result<()> {
    bail!(NO_KERNEL_TUN)
}

/// No capability an app can be granted opens a kernel TUN on Android.
pub fn ensure_net_admin_for_l3() -> bool {
    false
}

pub fn l3_grant_pending() -> Option<String> {
    None
}

pub fn l3_blocker() -> Option<String> {
    Some(NO_KERNEL_TUN.to_string())
}

/// /etc/hosts is read-only for apps; `.mesh` names go through the SOCKS proxy.
pub fn ensure_hosts_writable() {}
