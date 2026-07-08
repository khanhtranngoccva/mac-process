//! A high-level process monitor for a process.
pub mod args;
pub mod audit_token;
mod dead_processes;
pub mod region_iterator;
pub mod regions;
pub mod vnode;

use crate::{
    helpers::hashes,
    libproc::{
        args::ProcArgs2,
        bindings::proc_vnodepathinfo,
        bsd_info::BSDInfo,
        region_info::{RegionInfo, RegionWithPathInfo},
    },
    monitor::{
        args::ProcessArgInfo,
        regions::{Region, RegionWithPath},
        vnode::{Openable, ProcessVnodePaths, VnodeStat, VnodeWithPath},
    },
};
use audit_token::AuditToken;
use crossbeam::channel::Receiver;
use dashmap::DashMap;
use dead_processes::{DeadProcTracker, WatchItem};
use once_cell::sync::OnceCell;
use region_iterator::{RegionIterator, RegionWithPathIterator};
use rustix::{
    fs::{Dev, Gid, OFlags, Uid},
    process::Pid,
};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fmt::Debug,
    fs::File,
    io::{self},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Primary structure for querying live processes.
pub struct ProcessMonitor {
    // A mapping of PIDs to process information.
    mapping: Arc<DashMap<Pid, Weak<Process>>>,
    // kqueue-based dead process monitor.
    dead_monitor: DeadProcTracker,
    // A stale count that informs cleanup operation. This metric is advisory-only and may not be correct.
    collector_stale_count: Arc<AtomicU64>,
}

impl Debug for ProcessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessIntegrity")
            .field("mapping", &self.mapping)
            .finish()
    }
}

impl ProcessMonitor {
    /// Creates a new integrity monitor. It should be shared across an entire application to prevent excessive memory consumption.
    pub fn new() -> Result<Self, io::Error> {
        let mapping = Arc::new(DashMap::new());
        Ok(Self {
            mapping,
            dead_monitor: DeadProcTracker::build()?,
            collector_stale_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Gets a process by PID, and returns an error if the process is not found or is dead.
    pub fn get(&self, pid: Pid) -> Result<Arc<Process>, io::Error> {
        self.auto_cleanup();
        Process::gather(self, pid)
    }

    /// Removes a process entry. The weakref in the value must match to prevent race conditions where new unrelated entries may get removed.
    fn clear_one_internal(&self, pid: Pid, weakref: &Weak<Process>) -> bool {
        self.mapping
            .remove_if(&pid, |_, weakref_other| {
                Weak::ptr_eq(weakref, weakref_other)
            })
            .is_some()
    }

    /// Removes entries that have no strong references to free memory.
    fn clear_stale(&self) {
        self.mapping
            .retain(|_, weakref| Weak::strong_count(weakref) > 0)
    }

    /// Performs automatic cleanups.
    fn auto_cleanup(&self) {
        if self.collector_stale_count.load(Ordering::Relaxed) > 200 {
            self.collector_stale_count.store(0, Ordering::Relaxed);
            self.clear_stale();
        }
    }
}

/// Structure for tracking a live process.
pub struct Process {
    pid: Pid,
    audit_token: AuditToken,
    /// The executable path of the process.
    path: OnceCell<PathBuf>,
    /// The name of the process.
    name: OnceCell<OsString>,
    /// The identity of the main executable is a tuple of the device and inode.
    exe_identity: OnceCell<(Dev, u64)>,
    /// The MD5 hash of the main executable.
    md5_exe: OnceCell<[u8; 16]>,
    /// The SHA256 hash of the main executable.
    sha256_exe: OnceCell<[u8; 32]>,
    /// Alive status as reported by kqueue.
    kqueue_alive: Arc<AtomicBool>,
    /// Channel to wait until process is dead.
    kqueue_notify_dead: Receiver<()>,
    /// If set to false, prevents incrementing the stale count.
    collector_mark_stale_on_drop: AtomicBool,
    /// Once dropped, the stale count increments up to a certain point, which informs the automatic cleanup operation.
    collector_stale_count: Arc<AtomicU64>,
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid)
            .field("audit_token", &self.audit_token)
            .field("exe_identity", &self.exe_identity)
            .field("path", &self.path)
            .field("name", &self.name)
            .finish()
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        self.audit_token == other.audit_token
    }
}

impl Process {
    fn gather(collector: &ProcessMonitor, pid: Pid) -> Result<Arc<Self>, io::Error> {
        // When the process is uncached and not found, an error must be returned.
        // When the process is cached and is dead, the item should be expunged from cache.
        loop {
            let mut _new_proc_ref = None;
            let process = collector
                .mapping
                .entry(pid)
                .or_try_insert_with(|| -> Result<_, io::Error> {
                    let audit_token = AuditToken::from_pid(pid).map_err(|_| {
                        io::Error::new(io::ErrorKind::NotFound, "process is not alive")
                    })?;
                    let kqueue_alive = Arc::new(AtomicBool::new(true));
                    let (kqueue_dead_tx, kqueue_dead_rx) = crossbeam::channel::bounded(1);
                    let item = WatchItem {
                        pid,
                        live_flag: kqueue_alive.clone(),
                        notify: kqueue_dead_tx,
                    };
                    collector.dead_monitor.send_item(item)?;
                    let proc_ref = Arc::new(Self {
                        pid,
                        audit_token,
                        md5_exe: OnceCell::new(),
                        sha256_exe: OnceCell::new(),
                        path: OnceCell::new(),
                        name: OnceCell::new(),
                        exe_identity: OnceCell::new(),
                        kqueue_notify_dead: kqueue_dead_rx,
                        kqueue_alive,
                        collector_mark_stale_on_drop: AtomicBool::new(true),
                        collector_stale_count: collector.collector_stale_count.clone(),
                    });
                    let weak_proc_ref = Arc::downgrade(&proc_ref);
                    _new_proc_ref = Some(proc_ref);
                    Ok(weak_proc_ref)
                })?
                .clone();
            let process = match process.upgrade() {
                None => {
                    collector.clear_one_internal(pid, &process);
                    continue;
                }
                Some(p) if !p.is_alive() => {
                    // Since the entry is removed, we do not need to increment the count to avoid invoking auto_cleanup too much.
                    if collector.clear_one_internal(pid, &process) {
                        p.collector_mark_stale_on_drop
                            .store(false, Ordering::Relaxed);
                    };
                    continue;
                }
                Some(p) => p,
            };
            break Ok(process);
        }
    }

    /// Checks if the process is alive.
    pub fn is_alive(&self) -> bool {
        // The alive check uses 2 mechanisms:
        // - The audit_token querying mechanism. If the process behind the PID is dead without any other processes reusing its PID, the audit token cannot be queried. If the audit token is queried and but the PID version mismatches, the process is implied dead.
        // - In case a threat actor attempts to cycle through the 32-bit PID version namespace to replace itself, the kqueue should generally be able to mark the process as dead long before the attempt is complete.
        if !self.kqueue_alive.load(Ordering::Acquire) {
            return false;
        }
        let initial_audit_token = self.audit_token();
        let current_audit_token = match AuditToken::from_pid(self.pid) {
            Ok(audit_token) => audit_token,
            Err(_) => return false,
        };
        current_audit_token.pid() == initial_audit_token.pid()
            && current_audit_token.pidversion() == initial_audit_token.pidversion()
    }

    /// Waits until process is dead.
    pub fn wait_until_dead(&self) -> Result<(), io::Error> {
        if !self.is_alive() {
            return Ok(());
        }
        self.kqueue_notify_dead.recv().map_err(io::Error::other)
    }

    /// Evaluates a cached value, and returns an error if the process is not alive.
    pub fn evaluate_cached<'a, T>(
        &'a self,
        location: &'a OnceCell<T>,
        func: impl FnOnce() -> Result<T, io::Error>,
    ) -> Result<&'a T, io::Error> {
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        location.get_or_try_init(move || {
            if !self.is_alive() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "process is not alive",
                ));
            }
            func()
        })
    }

    /// Gets the path of the process (alias of [`Self::exe_path`]). This property is cached.
    #[inline]
    pub fn path(&self) -> Result<&Path, io::Error> {
        self.exe_path()
    }

    /// Gets the path of the main executable of the process. This property is cached.
    pub fn exe_path(&self) -> Result<&Path, io::Error> {
        self.evaluate_cached(&self.path, || {
            let path = crate::libproc::proc_pid::pidpath_audittoken(*self.audit_token.raw_token())?;
            Ok(path)
        })
        .map(|path| path.as_path())
    }

    /// Gets the path of the main executable of the process without caching. This allows the caller to retrieve the executable path again in case it is stale.
    pub fn exe_path_uncached(&self) -> Result<PathBuf, io::Error> {
        let path = crate::libproc::proc_pid::pidpath_audittoken(*self.audit_token.raw_token())?;
        // Sanity check to prevent returning a path for a dead process or another process.
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(path)
    }

    /// Gets the name of the process. This property is cached.
    pub fn name(&self) -> Result<&OsStr, io::Error> {
        self.evaluate_cached(&self.name, || {
            let name = crate::libproc::proc_pid::name(self.pid.as_raw_pid())?;
            Ok(name)
        })
        .map(|name| name.as_os_str())
    }

    /// Gets the name of the process without caching. This allows the caller to retrieve the process name again in case it is stale.
    pub fn name_uncached(&self) -> Result<OsString, io::Error> {
        let name = crate::libproc::proc_pid::name(self.pid.as_raw_pid())?;
        // Sanity check to prevent returning a name for a dead process or another process.
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(name)
    }

    /// Gets the PID of the process.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Gets the parent PID of the process.
    ///
    /// # Notes
    /// - The function does not return in the [`Pid`] type because macOS also has PID 0.
    pub fn ppid(&self) -> Result<u32, io::Error> {
        let info = crate::libproc::proc_pid::pidinfo::<BSDInfo>(self.pid.as_raw_pid(), 0)?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(info.pbi_ppid)
    }

    /// Gets the UID of the process.
    pub fn uid(&self) -> Result<Uid, io::Error> {
        let info = crate::libproc::proc_pid::pidinfo::<BSDInfo>(self.pid.as_raw_pid(), 0)?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(Uid::from_raw_unchecked(info.pbi_uid))
    }

    /// Gets the real UID of the process.
    pub fn ruid(&self) -> Result<Uid, io::Error> {
        let info = crate::libproc::proc_pid::pidinfo::<BSDInfo>(self.pid.as_raw_pid(), 0)?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(Uid::from_raw_unchecked(info.pbi_ruid))
    }

    /// Gets the GID of the process.
    pub fn gid(&self) -> Result<Gid, io::Error> {
        let info = crate::libproc::proc_pid::pidinfo::<BSDInfo>(self.pid.as_raw_pid(), 0)?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(Gid::from_raw_unchecked(info.pbi_gid))
    }

    /// Gets the real GID of the process.
    pub fn rgid(&self) -> Result<Gid, io::Error> {
        let info = crate::libproc::proc_pid::pidinfo::<BSDInfo>(self.pid.as_raw_pid(), 0)?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(Gid::from_raw_unchecked(info.pbi_rgid))
    }

    /// Gets the audit token of the process.
    pub fn audit_token(&self) -> &AuditToken {
        &self.audit_token
    }

    /// Obtains the information for a process region at a given offset.
    pub fn region_at(&self, offset: u64) -> Result<Region, io::Error> {
        let region_info =
            crate::libproc::proc_pid::pidinfo::<RegionInfo>(self.pid.as_raw_pid(), offset)?;
        // Sanity check to prevent returning a region info for a dead process or another process.
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(Region::from_raw(region_info))
    }

    /// Creates an iterator that yields information about virtual memory regions in a process.
    pub fn region_iterator<'a>(&'a self) -> RegionIterator<'a> {
        RegionIterator::new(self)
    }

    /// Obtains the information for a process path region at a given offset.
    pub fn region_with_path_at(&self, offset: u64) -> Result<RegionWithPath, io::Error> {
        let region_info =
            crate::libproc::proc_pid::pidinfo::<RegionWithPathInfo>(self.pid.as_raw_pid(), offset)?;
        // Sanity check to prevent returning a region info for a dead process or another process.
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(RegionWithPath::from_raw(region_info))
    }

    /// Creates an iterator that yields information about virtual memory regions with path information in a process.
    pub fn region_with_path_iterator<'a>(&'a self) -> RegionWithPathIterator<'a> {
        RegionWithPathIterator::new(self)
    }

    /// Retrieves the first text region with path information. This usually contains information about the main executable
    pub fn exe_region(&self) -> Result<RegionWithPath, io::Error> {
        // Approach is based on lsof: https://github.com/lsof-org/lsof/blob/6379888cc1924bf97b2cfdbc1cee38bb0aa45f5d/lib/dialects/darwin/dproc.c#L638
        let mut iterator = self.region_with_path_iterator();
        for _ in 0..10000 {
            let region = iterator.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no executable region with path found",
                )
            })??;
            if !region.vnode().path().as_os_str().is_empty() {
                return Ok(region);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no executable region with path found",
        ))
    }

    /// Retrieves the metadata of the main executable of the process.
    pub fn exe_stats(&self) -> Result<VnodeStat, io::Error> {
        self.exe_region()
            .map(|region| region.vnode().vnode().stat())
    }

    /// Retrieves the identity of the main executable. This property is cached.
    pub fn exe_identity(&self) -> Result<(Dev, u64), io::Error> {
        self.evaluate_cached(&self.exe_identity, || {
            let stats = self.exe_stats()?;
            Ok(stats.identity())
        })
        .cloned()
    }

    /// Retrieves the identity of the main executable without caching. This allows the caller to retrieve the executable identity again in case it is stale.
    pub fn exe_identity_uncached(&self) -> Result<(Dev, u64), io::Error> {
        let stats = self.exe_stats()?;
        Ok(stats.identity())
    }

    /// Opens the main executable of the process as a file by using volfs (/.vol) as a [`File`].
    /// Note that behavior may be unpredictable if the volume directory is shadowed or locked
    pub fn open_exe(&self, flags: OFlags) -> Result<File, io::Error> {
        let owned_fd = self.open_exe_fd(flags)?;
        Ok(File::from(owned_fd))
    }

    /// Opens the main executable of the process as a file by using volfs (/.vol) as a [`OwnedFd`].
    /// Note that behavior may be unpredictable if the volume directory is shadowed or locked
    pub fn open_exe_fd(&self, flags: OFlags) -> Result<OwnedFd, io::Error> {
        let region = self.exe_region()?;
        let vnode = region.vnode();
        vnode.open(flags)
    }

    /// Computes the MD5 hash of the main executable. This property is cached.
    #[doc(hidden)]
    pub fn md5_exe(&self) -> Result<[u8; 16], io::Error> {
        self.evaluate_cached(&self.md5_exe, || {
            let file = self.open_exe(OFlags::empty())?;
            hashes::compute_md5(file)
        })
        .copied()
    }

    /// Computes the MD5 hash of the main executable. This property is cached.
    #[inline]
    pub fn exe_md5(&self) -> Result<[u8; 16], io::Error> {
        self.md5_exe()
    }

    /// Computes the SHA256 hash of the main executable. This property is cached.
    #[doc(hidden)]
    pub fn sha256_exe(&self) -> Result<[u8; 32], io::Error> {
        self.evaluate_cached(&self.sha256_exe, || {
            let file = self.open_exe(OFlags::empty())?;
            hashes::compute_sha256(file)
        })
        .copied()
    }

    /// Computes the SHA256 hash of the main executable. This property is cached.
    #[inline]
    pub fn exe_sha256(&self) -> Result<[u8; 32], io::Error> {
        self.sha256_exe()
    }

    /// Retrieves the path information of the process.
    #[inline]
    pub fn vnode_path_info(&self) -> Result<ProcessVnodePaths, io::Error> {
        let vnode_path_info =
            crate::libproc::proc_pid::pidinfo::<proc_vnodepathinfo>(self.pid.as_raw_pid(), 0)?;
        // Sanity check to prevent returning a vnode path info for a dead process or another process.
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        Ok(ProcessVnodePaths::from_raw(vnode_path_info))
    }

    /// Retrieves the current working directory information of the process.
    #[inline]
    pub fn cwd(&self) -> Result<VnodeWithPath, io::Error> {
        let cwd = *self.vnode_path_info()?.cwd();
        Ok(cwd)
    }

    /// Retrieves the current working directory path of the process.
    ///
    /// This is shorthand for `process.cwd().path()`
    #[inline]
    pub fn cwd_path(&self) -> Result<PathBuf, io::Error> {
        self.cwd().map(|cwd| cwd.path().to_path_buf())
    }

    /// Opens the cwd as an [`OwnedFd`].
    ///
    /// Note that behavior may be unpredictable if the volume directory is shadowed or locked
    pub fn open_cwd(&self, flags: OFlags) -> Result<OwnedFd, io::Error> {
        let cwd = self.cwd()?;
        cwd.open(flags)
    }

    /// Retrieves the root directory information of the process.
    #[inline]
    pub fn root(&self) -> Result<VnodeWithPath, io::Error> {
        let root = *self.vnode_path_info()?.root();
        Ok(root)
    }

    /// Retrieves the root directory path of the process.
    ///
    /// This is shorthand for `process.root().path()`
    #[inline]
    pub fn root_path(&self) -> Result<PathBuf, io::Error> {
        self.root().map(|root| root.path().to_path_buf())
    }

    /// Opens the root as an [`OwnedFd`].
    ///
    /// Note that behavior may be unpredictable if the volume directory is shadowed or locked
    pub fn open_root(&self, flags: OFlags) -> Result<OwnedFd, io::Error> {
        let root = self.root()?;
        root.open(flags)
    }

    /// Retrieves the arguments and environment variables of the process.
    pub fn arg_info(&self) -> Result<ProcessArgInfo, io::Error> {
        let raw = crate::libproc::proc_pid::proc_args2_raw(self.pid.as_raw_pid())?;
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process is not alive",
            ));
        }
        let args = ProcessArgInfo::parse(&ProcArgs2::from_raw(&raw)?);
        Ok(args)
    }

    /// Retrieves the process' command line arguments.
    pub fn args(&self) -> Result<Vec<OsString>, io::Error> {
        let args = self.arg_info()?.args;
        Ok(args)
    }

    /// Retrieves the process' environment variables.
    pub fn env(&self) -> Result<HashMap<OsString, OsString>, io::Error> {
        let environment = self.arg_info()?.environment;
        Ok(environment)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.collector_mark_stale_on_drop.load(Ordering::Relaxed) {
            self.collector_stale_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
use std::process::Child;

#[cfg(test)]
fn spawn_example_process() -> Child {
    use std::process::Command;
    use std::process::Stdio;
    Command::new("/bin/bash")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .env("malformed\"", "env_var")
        .spawn()
        .expect("Failed to spawn process")
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::{ProcessMonitor, helpers::hashes};
    use rustix::{fs::OFlags, process::Pid};

    use super::spawn_example_process;

    #[test]
    fn test_process_liveness_and_path() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        let path = process.path().expect("failed to get process path");
        println!("Process path: {}", path.display());
        child.kill().expect("failed to kill process");
        let _ = child.wait_with_output();
        assert!(!process.is_alive(), "process should be dead");
    }

    #[test]
    fn test_process_kqueue_wait() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        child.kill().expect("failed to kill process");
        process
            .wait_until_dead()
            .expect("failed to wait for process");
        let _ = child.wait_with_output();
        assert!(!process.is_alive(), "process should be dead");
    }

    #[test]
    fn test_audit_token() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        let audit_token = process.audit_token();
        println!("Audit token: {:?}", audit_token);
        assert!(audit_token.pid().expect("failed to retrieve ID") == child_pid);
        child.kill().expect("failed to kill process");
        let _ = child.wait_with_output();
    }

    #[test]
    fn test_open_exe() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        let _exe = process
            .open_exe(OFlags::empty())
            .expect("failed to open exe");
        child.kill().expect("failed to kill process");
        let _ = child.wait_with_output();
    }

    #[test]
    fn test_hashes() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        let md5 = process.md5_exe().expect("failed to get md5 hash");
        let sha256 = process.sha256_exe().expect("failed to get sha256 hash");
        println!("MD5 hash: {:?}", md5);
        println!("SHA256 hash: {:?}", sha256);
        child.kill().expect("failed to kill process");
        let _ = child.wait_with_output();
        // Compare with the original /bin/bash
        let file = File::open("/bin/bash").expect("failed to open /bin/bash");
        let md5_original = hashes::compute_md5(file).expect("failed to compute md5 hash");
        let file = File::open("/bin/bash").expect("failed to open /bin/bash");
        let sha256_original = hashes::compute_sha256(file).expect("failed to compute sha256 hash");
        println!("MD5 hash (original): {:?}", md5_original);
        println!("SHA256 hash (original): {:?}", sha256_original);
        assert!(md5 == md5_original);
        assert!(sha256 == sha256_original);
    }

    #[test]
    fn test_arg_info() {
        let mut child = spawn_example_process();
        let child_pid = child.id();
        let integrity = ProcessMonitor::new().expect("failed to create integrity object");
        let process = integrity
            .get(Pid::from_raw(child_pid as i32).expect("failed to convert pid"))
            .expect("failed to get process");
        let arg_info = process.arg_info().expect("failed to get arg info");
        println!("Arg info: {:?}", arg_info);
        child.kill().expect("failed to kill process");
        let _ = child.wait_with_output();
    }
}
