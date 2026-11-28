//! The sim's device store and its disk.
//!
//! `NoStore` answers every call instantly, so a slow disk could never show up
//! in the sim. [`SimStore`] keeps the records the daemon writes in memory and
//! makes every MUTATING call one durable write on the node's [`SimDisk`],
//! mirroring the real `DeviceStore`, where each mutating port method is one
//! locked read-modify-write of `devices.json` with an fsync
//! (`with_devices_mut`), whatever the call site.
//!
//! A write takes the disk's current write latency. The latency is a property
//! of the disk (the `SlowDisk` fault sets it for every write on that node); it
//! never depends on which method or call site wrote. A write made while the
//! daemon loop itself is being polled is charged to the loop
//! (`sim_rt::charge_blocking_ms`), which is what production would have held
//! its event loop for. A write made from a blocking thread or another task is
//! not.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use filament_id::DeviceCert;
use serde_json::Value;

use crate::recv::ports::RecvStore;

/// One node's disk: the latency every durable write takes right now.
#[derive(Debug, Default)]
pub struct SimDisk {
    write_ms: AtomicU64,
    /// Writes charged to the daemon loop, with their latency (for the trace).
    loop_writes: Mutex<Vec<(u64, &'static str, u64)>>,
}

impl SimDisk {
    pub fn set_write_ms(&self, ms: u64) {
        self.write_ms.store(ms, Ordering::Relaxed);
    }

    pub fn write_ms(&self) -> u64 {
        self.write_ms.load(Ordering::Relaxed)
    }

    /// One durable write (a temp write, an fsync and a rename).
    fn durable_write(&self, what: &'static str) {
        let ms = self.write_ms();
        if ms == 0 {
            return;
        }
        if crate::sim_rt::charge_blocking_ms(ms) {
            let at = filament_transport::clock::now_ms();
            self.loop_writes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((at, what, ms));
        }
    }

    /// The writes charged to the loop so far, oldest first.
    pub fn take_loop_writes(&self) -> Vec<(u64, &'static str, u64)> {
        std::mem::take(&mut *self.loop_writes.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// The device records the daemon wrote: name to the device key its
/// certificate names (if it stored one). Survives a restart of the node.
#[derive(Default)]
pub struct SimStore {
    disk: Arc<SimDisk>,
    records: Mutex<BTreeMap<String, Option<[u8; 32]>>>,
}

impl SimStore {
    pub fn new(disk: Arc<SimDisk>) -> Self {
        Self {
            disk,
            records: Mutex::new(BTreeMap::new()),
        }
    }

    /// The record name holding `device_pub`, as the real store resolves a
    /// proven certificate key to the device it was stored under.
    pub fn name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(_, k)| k.as_ref() == Some(device_pub))
            .map(|(n, _)| n.clone())
    }

    fn put(&self, name: &str, device_pub: Option<[u8; 32]>) {
        let mut g = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let slot = g.entry(name.to_string()).or_insert(None);
        if device_pub.is_some() {
            *slot = device_pub;
        }
    }
}

impl RecvStore for SimStore {
    fn devices_path(&self) -> PathBuf {
        PathBuf::new()
    }

    fn devices_touch(
        &self,
        _name: &str,
        _v6: Option<std::net::Ipv6Addr>,
        _v4: Option<std::net::Ipv4Addr>,
    ) {
        self.disk.durable_write("devices_touch");
    }

    fn devices_remove(&self, name: &str) -> anyhow::Result<()> {
        self.disk.durable_write("devices_remove");
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
        Ok(())
    }

    fn devices_store(&self, name: &str, _secret: &str) -> anyhow::Result<String> {
        self.disk.durable_write("devices_store");
        self.put(name, None);
        Ok(name.to_string())
    }

    fn devices_store_new(
        &self,
        name: &str,
        _secret: &str,
        _introduced_by: Option<&str>,
    ) -> anyhow::Result<String> {
        self.disk.durable_write("devices_store_new");
        self.put(name, None);
        Ok(name.to_string())
    }

    fn device_was_introduced(&self, _name: &str) -> bool {
        false
    }

    fn devices_sweep_lapsed(&self, _now: u64) -> usize {
        // The real sweep always rewrites devices.json (with_devices_mut).
        self.disk.durable_write("devices_sweep_lapsed");
        0
    }

    fn devices_upsert_atomic(
        &self,
        name: &str,
        _secret: Option<&str>,
        cert: Option<&DeviceCert>,
        _caps: Option<&[String]>,
        _scope: Option<u8>,
        _user_key_hex: Option<&str>,
        _delegated: Option<(&[String], u64, u64, u64)>,
        _allow_reanchor: bool,
    ) -> anyhow::Result<String> {
        self.disk.durable_write("devices_upsert_atomic");
        self.put(name, cert.map(|c| c.device_pub));
        Ok(name.to_string())
    }

    fn promote_provisional_identity(
        &self,
        name: &str,
        cert: &DeviceCert,
        _scope: u8,
    ) -> anyhow::Result<()> {
        self.disk.durable_write("promote_provisional_identity");
        self.put(name, Some(cert.device_pub));
        Ok(())
    }

    fn mark_bounded_cap_source(
        &self,
        _name: &str,
        _capability: &str,
        _source: &str,
    ) -> anyhow::Result<()> {
        self.disk.durable_write("mark_bounded_cap_source");
        Ok(())
    }

    fn merge_owner_cap_ops(&self, ops: &[Value]) -> usize {
        // The real merge returns before taking the lock on an empty batch.
        if !ops.is_empty() {
            self.disk.durable_write("merge_owner_cap_ops");
        }
        0
    }

    fn owner_signed_cap_ops(&self) -> Vec<Value> {
        Vec::new()
    }

    fn mark_lapsed_now(&self, _device_pub: &[u8; 32]) -> Option<String> {
        self.disk.durable_write("mark_lapsed_now");
        None
    }

    fn sanitize_device_name(&self, name: &str) -> String {
        name.to_string()
    }

    fn devices_find_by_device_pub(&self, _device_pub: &[u8; 32]) -> Option<Value> {
        None
    }

    fn any_shell_grant(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn a_write_charges_the_loop_only_inside_its_scope() {
        let disk = Arc::new(SimDisk::default());
        disk.set_write_ms(1_200);
        let store = Arc::new(SimStore::new(disk.clone()));
        // Outside a loop poll: a blocking thread or another task.
        store.devices_sweep_lapsed(0);
        assert!(disk.take_loop_writes().is_empty());
        let s2 = store.clone();
        let charged = crate::sim_rt::LoopScoped::new(async move {
            let before = crate::sim_rt::loop_charged_ms();
            s2.devices_sweep_lapsed(0);
            crate::sim_rt::loop_charged_ms() - before
        })
        .await;
        assert_eq!(charged, 1_200);
        assert_eq!(disk.take_loop_writes().len(), 1);
        // A fast disk charges nothing.
        disk.set_write_ms(0);
        let s3 = store.clone();
        let charged = crate::sim_rt::LoopScoped::new(async move {
            s3.devices_touch("x", None, None);
            crate::sim_rt::loop_charged_ms()
        })
        .await;
        assert_eq!(charged, 0);
    }
}
