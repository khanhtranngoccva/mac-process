//! Types and functions for information about processes by PID
use std::env;
use std::ffi::OsString;
use std::io;
use std::mem;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use libc::c_int;
use libc::pid_t;

use crate::helpers::syscall;
use crate::libproc::bindings::audit_token_t;
use crate::libproc::bindings::proc_pidpath_audittoken;
use crate::libproc::bindings::{
    PROC_PIDLISTFDS, PROC_PIDLISTTHREADS, PROC_PIDPATHINFO, PROC_PIDPATHINFO_MAXSIZE,
    PROC_PIDREGIONINFO, PROC_PIDREGIONPATHINFO, PROC_PIDTASKALLINFO, PROC_PIDTASKINFO,
    PROC_PIDTBSDINFO, PROC_PIDTHREADINFO, PROC_PIDTHREADPATHINFO, PROC_PIDVNODEPATHINFO,
    PROC_PIDWORKQUEUEINFO, proc_libversion, proc_name, proc_pidinfo, proc_pidpath,
    proc_regionfilename,
};
use crate::libproc::bsd_info::BSDInfo;
use crate::libproc::kinfo::{KProcInfo, KinfoProc};
use crate::libproc::processes;
use crate::libproc::task_info::{TaskAllInfo, TaskInfo};
use crate::libproc::thread_info::ThreadInfo;
use crate::libproc::work_queue_info::WorkQueueInfo;
use libc::c_void;

/// An enum used to specify what type of information about a process is referenced
/// See <http://opensource.apple.com/source/xnu/xnu-1504.7.4/bsd/kern/proc_info.c>
#[repr(u32)]
pub enum PidInfoFlavor {
    /// List of file descriptors
    ListFDs = PROC_PIDLISTFDS,
    /// All information about the task
    TaskAllInfo = PROC_PIDTASKALLINFO,
    /// Information about the task's BSD information
    TBSDInfo = PROC_PIDTBSDINFO,
    /// Information about the task
    TaskInfo = PROC_PIDTASKINFO,
    /// Information about the thread
    ThreadInfo = PROC_PIDTHREADINFO,
    /// List of threads
    ListThreads = PROC_PIDLISTTHREADS,
    /// Information about the region
    RegionInfo = PROC_PIDREGIONINFO,
    /// Information about the region's path
    RegionPathInfo = PROC_PIDREGIONPATHINFO,
    /// Information about the vnode path
    VNodePathInfo = PROC_PIDVNODEPATHINFO,
    /// Information about the thread's path
    ThreadPathInfo = PROC_PIDTHREADPATHINFO,
    /// Information about the path
    PathInfo = PROC_PIDPATHINFO,
    /// Information about the work queue
    WorkQueueInfo = PROC_PIDWORKQUEUEINFO,
}

/// The `ListPIDInfo` trait is needed for polymorphism on listpidinfo types, also abstracting flavor in order to provide
/// type-guaranteed flavor correctness
pub trait ListPIDInfo {
    /// Item
    type Item;
    /// Return the `PidInfoFlavor` of the implementing struct
    fn flavor() -> PidInfoFlavor;
}

/// The `ProcType` type. Used to specify what type of processes you are interested
/// in other calls, such as `listpids`.
#[derive(Copy, Clone)]
pub enum ProcType {
    /// All processes
    ProcAllPIDS = 1,
    /// Only PGRP Processes
    ProcPGRPOnly = 2,
    /// Only TTY Processes
    ProcTTYOnly = 3,
    /// Only UID Processes
    ProcUIDOnly = 4,
    /// Only RUID Processes
    ProcRUIDOnly = 5,
    /// Only PPID Processes
    ProcPPIDOnly = 6,
}

/// The `PIDInfo` trait is needed for polymorphism on pidinfo types, also abstracting flavor provides
/// type-guaranteed flavor correctness
pub trait PIDInfo {
    /// Return the `PidInfoFlavor` of the implementing struct
    fn flavor() -> PidInfoFlavor;
}

/// The `PidInfo` enum contains a piece of information about processes
#[allow(clippy::large_enum_variant)]
pub enum PidInfo {
    /// File Descriptors used by Process
    ListFDs(Vec<i32>),
    /// Get all Task Info
    TaskAllInfo(TaskAllInfo),
    /// Get `TBSDInfo`
    TBSDInfo(BSDInfo),
    /// Single Task Info
    TaskInfo(TaskInfo),
    /// `ThreadInfo`
    ThreadInfo(ThreadInfo),
    /// A list of Thread IDs
    ListThreads(Vec<i32>),
    /// `RegionInfo`
    RegionInfo(String),
    /// `RegionPathInfo`
    RegionPathInfo(String),
    /// `VNodePathInfo`
    VNodePathInfo(String),
    /// `ThreadPathInfo`
    ThreadPathInfo(String),
    /// `PathInfo` of the executable being run as the process
    PathInfo(String),
    /// `WorkQueueInfo`
    WorkQueueInfo(WorkQueueInfo),
}

/// Struct for List of Threads
pub struct ListThreads;

impl ListPIDInfo for ListThreads {
    type Item = u64;
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::ListThreads
    }
}

/// Map `ProcType` to the new `ProcFilter` enum; the values match the now
/// deprecated implementation of `listpids`
impl From<ProcType> for processes::ProcFilter {
    fn from(proc_type: ProcType) -> Self {
        use processes::ProcFilter;

        match proc_type {
            ProcType::ProcAllPIDS => ProcFilter::All,
            ProcType::ProcPGRPOnly => ProcFilter::ByProgramGroup { pgrpid: 0 },
            ProcType::ProcTTYOnly => ProcFilter::ByTTY { tty: 0 },
            ProcType::ProcUIDOnly => ProcFilter::ByUID { uid: 0 },
            ProcType::ProcRUIDOnly => ProcFilter::ByRealUID { ruid: 0 },
            ProcType::ProcPPIDOnly => ProcFilter::ByParentProcess { ppid: 0 },
        }
    }
}

/// Returns the PIDs of the active processes that match the `proc_types` parameter
///
/// # Note
///
/// This function is deprecated in favor of
/// [`libproc::processes::pids_by_type()`][crate::processes::pids_by_type],
/// which lets you specify what PGRP / TTY / UID / RUID / PPID you want to filter by
#[allow(clippy::missing_errors_doc)]
#[deprecated(
    since = "0.13.0",
    note = "Please use `libproc::processes::pids_by_type()` instead."
)]
pub fn listpids(proc_types: ProcType) -> Result<Vec<u32>, io::Error> {
    processes::pids_by_type(proc_types.into())
}

/// Search through the current processes looking for open file references which match
/// a specified path or volume.
///
/// # Note
///
/// This function is deprecated in favor of
/// [`libproc::processes::pids_by_type_and_path()`][crate::processes::pids_by_type_and_path],
/// which lets you specify what PGRP / TTY / UID / RUID / PPID you want to
/// filter by.
///
#[allow(clippy::missing_errors_doc)]
#[deprecated(
    since = "0.13.0",
    note = "Please use `libproc::processes::pids_by_type_and_path()` instead."
)]
pub fn listpidspath(proc_types: ProcType, path: &str) -> Result<Vec<u32>, io::Error> {
    processes::pids_by_type_and_path(proc_types.into(), &PathBuf::from(path), false, false)
}

/// Get info about a process, task, thread or work queue by specifying the appropriate type for `T`.
///
/// # Type Parameter Variants
///
/// ## `BSDInfo`
/// Returns BSD-level process information (pid, ppid, uid, gid, tty, process name, flags, etc.).
/// The `arg` parameter is unused and should be `0`.
/// - Requires root to query pid=0 (kernel task)
/// - Most other processes can be queried without special privileges
///
/// ## `TaskInfo`
/// Returns Mach task-level information (virtual/resident memory sizes, page faults,
/// thread count, CPU times, etc.). The `arg` parameter is unused and should be `0`.
/// - Requires root to query pid=0 (kernel task)
///
/// ## `TaskAllInfo`
/// Returns both `BSDInfo` and `TaskInfo` in a single call.
/// The `arg` parameter is unused and should be `0`.
/// - Requires root to query pid=0 (kernel task)
///
/// ## `ThreadInfo`
/// Returns information about a specific thread (run state, flags, CPU usage, priority, etc.).
/// **Important**: The `arg` parameter must be a valid thread ID for the target process.
/// - First call `listpidinfo::<ListThreads>()` to get the list of thread IDs
/// - Then use one of those thread IDs as the `arg` parameter
/// - Passing `arg=0` will fail unless the process happens to have a thread with ID 0
/// - Returns `ESRCH` ("No such process") if the thread ID is invalid
///
/// ## `WorkQueueInfo`
/// Returns Grand Central Dispatch (GCD) work queue information (thread counts).
/// The `arg` parameter is unused and should be `0`.
/// - **Important**: Only works for processes that use GCD/libdispatch work queues
/// - Returns `ESRCH` ("No such process") if the process has no work queue allocated
/// - Work queues are lazily created only when a process uses `dispatch_async()` or similar
/// - Returns `EPERM` ("Operation not permitted") for privileged system processes like
///   pid=1 (launchd) unless running as root
///
/// # Errors
///
/// Will return an error if underlying Darwin `proc_pidinfo` returns an error or sets `errno`.
/// Common errors include:
/// - `ESRCH` - No such process, or (for ThreadInfo/WorkQueueInfo) the requested
///   thread/work queue doesn't exist
/// - `EPERM` - Operation not permitted (insufficient privileges)
/// - Custom error for pid=0 when not running as root
///
/// # Examples
///
/// ```
/// use std::io::Write;
/// use mac_process::libproc::proc_pid::pidinfo;
/// use mac_process::libproc::bsd_info::BSDInfo;
/// use mac_process::libproc::task_info::{TaskAllInfo, TaskInfo};
/// use std::process;
/// use mac_process::libproc::thread_info::ThreadInfo;
/// use mac_process::libproc::work_queue_info::WorkQueueInfo;
///
/// let pid = process::id() as i32;
///
/// // Get the `BSDInfo` for the process with pid 0
/// match pidinfo::<BSDInfo>(pid, 0) {
///     Ok(info) => assert_eq!(info.pbi_pid as i32, pid),
///     Err(err) => eprintln!("Error retrieving process info: {}", err)
/// };
///
/// // Get the `TaskInfo` for the process with pid 0
/// match pidinfo::<TaskInfo>(pid, 0) {
///     Ok(info) => assert!(info.pti_threadnum  > 0),
///     Err(err) => eprintln!("Error retrieving process info: {}", err)
/// };
///
/// // Get the `TaskAllInfo` for the process with pid 0
/// match pidinfo::<TaskAllInfo>(pid, 0) {
///     Ok(info) => {
///         assert_eq!(info.pbsd.pbi_pid as i32, pid);
///         assert!(info.ptinfo.pti_threadnum  > 0);
///     }
///     Err(err) => eprintln!("Error retrieving process info: {}", err)
/// };
///
/// // Get the `ThreadInfo` for the process with pid 0
/// match pidinfo::<ThreadInfo>(pid, 0) {
///     Ok(info) => assert!(!info.pth_name.is_empty()),
///     Err(err) => eprintln!("Error retrieving process info: {}", err)
/// };
///
/// // Get the `WorkQueueInfo` for the process with pid 0
/// match pidinfo::<WorkQueueInfo>(pid, 0) {
///     Ok(info) => assert!(info.pwq_nthreads > 0),
///     Err(err) => eprintln!("Error retrieving process info: {}", err)
/// };
/// ```
pub fn pidinfo<T: PIDInfo>(pid: i32, arg: u64) -> Result<T, io::Error> {
    // You cannot request information about the kernel task (pid=0) unless you are root

    use std::mem::MaybeUninit;

    use crate::helpers::syscall;
    if pid == 0 && !am_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Cannot request information about kernel task (pid=0) unless running as root",
        ));
    }

    let flavor = T::flavor() as i32;
    // No type `T` will be bigger than `i32::MAX`!!
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = size_of::<T>();
    let mut pidinfo = MaybeUninit::<T>::uninit();
    #[allow(clippy::pedantic)]
    let buffer_ptr = &mut pidinfo as *mut _ as *mut c_void;

    let bytes_read = syscall::cvt_positive(unsafe {
        proc_pidinfo(pid, flavor, arg, buffer_ptr, buffer_size as _)
    })? as usize;
    if bytes_read < buffer_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Insufficient bytes read: {} < {}", bytes_read, buffer_size),
        ));
    }
    Ok(unsafe { pidinfo.assume_init() })
}

#[cfg(any(target_os = "macos", doc))]
/// Get the filename associated with a memory region
///
/// # Errors
///
/// Will return an error if underlying Darwin function `proc_regionfilename` returns an error.
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::regionfilename;
///
/// // This checks that it can find the regionfilename of the region at address 0, of the init process with PID 1
/// use mac_process::libproc::proc_pid::am_root;
///
/// if am_root() {
///     match regionfilename(1, 0) {
///         Ok(regionfilename) => println!("Region Filename (at address = 0) of init process PID = 1 is '{}'", regionfilename.display()),
///         Err(err) => eprintln!("Error: {}", err)
///     }
/// }
/// ```
pub fn regionfilename(pid: i32, address: u64) -> Result<OsString, io::Error> {
    use crate::helpers::syscall;

    let mut buf: Vec<u8> = Vec::with_capacity((PROC_PIDPATHINFO_MAXSIZE - 1) as _);
    let buffer_ptr = buf.as_mut_ptr().cast::<c_void>();
    // PROC_PIDPATHINFO_MAXSIZE will be smaller than `u32::MAX`
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = buf.capacity() as u32;

    let ret = syscall::cvt_positive(unsafe {
        proc_regionfilename(pid, address, buffer_ptr, buffer_size)
    })? as usize;
    unsafe { buf.set_len(ret) };
    Ok(OsString::from_vec(buf))
}

/// Get the path of the executable file being run for a process
///
/// # Errors
///
/// Will return an error if underlying Darwin function `proc_pidpath` returns an error.
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::pidpath;
///
/// match pidpath(1) {
///     Ok(path) => println!("Path of init process with PID = 1 is '{}'", path.display()),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn pidpath(pid: i32) -> Result<PathBuf, io::Error> {
    let mut buf: Vec<u8> = Vec::with_capacity((PROC_PIDPATHINFO_MAXSIZE - 1) as _);
    let buffer_ptr = buf.as_mut_ptr().cast::<c_void>();
    // PROC_PIDPATHINFO_MAXSIZE will be smaller than `u32::MAX`
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = buf.capacity() as u32;
    let ret =
        syscall::cvt_positive(unsafe { proc_pidpath(pid, buffer_ptr, buffer_size as _) })? as usize;
    unsafe { buf.set_len(ret) };
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Get the path of the executable file being run for a process
///
/// # Errors
///
/// Will return an error if underlying Darwin function `proc_pidpath` returns an error.
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::pidpath;
///
/// match pidpath(1) {
///     Ok(path) => println!("Path of init process with PID = 1 is '{}'", path.display()),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn pidpath_audittoken(mut audit_token: audit_token_t) -> Result<PathBuf, io::Error> {
    let mut buf: Vec<u8> = Vec::with_capacity((PROC_PIDPATHINFO_MAXSIZE - 1) as _);
    let buffer_ptr = buf.as_mut_ptr().cast::<c_void>();
    // PROC_PIDPATHINFO_MAXSIZE will be smaller than `u32::MAX`
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = buf.capacity() as u32;
    let ret = syscall::cvt_positive(unsafe {
        proc_pidpath_audittoken(&mut audit_token, buffer_ptr, buffer_size as _)
    })? as usize;
    unsafe { buf.set_len(ret) };
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Get the major and minor version numbers of the native libproc library (Mac OS X)
///
/// # Errors
///
/// Should never return an error, but the `Result` return type is used for consistency with
/// other methods, and potential future use.
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid;
///
/// match proc_pid::libversion() {
///     Ok((major, minor)) => println!("Libversion: {}.{}", major, minor),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn libversion() -> Result<(i32, i32), io::Error> {
    let mut major = 0;
    let mut minor = 0;
    let ret: i32;

    unsafe {
        ret = proc_libversion(&raw mut major, &raw mut minor);
    };

    // return value of 0 indicates success (inconsistent with other functions... :-( )
    if ret == 0 {
        Ok((major, minor))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Get the name of a process, using its process id (pid)
///
/// # Errors
///
/// Will return an error if Darwin's `proc_pidinfo` returns 0
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid;
///
/// match proc_pid::name(1) {
///     Ok(name) => println!("Name: {}", name.display()),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn name(pid: i32) -> Result<OsString, io::Error> {
    let mut namebuf: Vec<u8> = Vec::with_capacity((PROC_PIDPATHINFO_MAXSIZE - 1) as _);
    let buffer_ptr = namebuf.as_ptr() as *mut c_void;
    // No type `T` will be bigger than `i32::MAX`!!
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = namebuf.capacity() as u32;

    let ret = syscall::cvt_positive(unsafe { proc_name(pid, buffer_ptr, buffer_size) })? as usize;
    unsafe { namebuf.set_len(ret) };
    Ok(OsString::from_vec(namebuf))
}

/// Get information on all running processes.
///
/// `max_len` is the maximum length of the array to return.
/// The length of the returned value: `Vec<T::Item>` may be less than `max_len`.
///
/// # Errors
///
/// Will return an error if Darwin's `proc_pidinfo` returns 0
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::{listpidinfo, pidinfo};
/// use mac_process::libproc::task_info::TaskAllInfo;
/// use mac_process::libproc::file_info::{ListFDs, ProcFDType};
/// use std::process;
///
/// let pid = process::id() as i32;
///
/// if let Ok(info) = pidinfo::<TaskAllInfo>(pid, 0) {
///     if let Ok(fds) = listpidinfo::<ListFDs>(pid, info.pbsd.pbi_nfiles as usize) {
///         for fd in &fds {
///             let fd_type = ProcFDType::from(fd.proc_fdtype);
///             println!("File Descriptor: {}, Type: {:?}", fd.proc_fd, fd_type);
///         }
///     }
/// }
/// ```
pub fn listpidinfo<T: ListPIDInfo>(pid: i32, max_len: usize) -> Result<Vec<T::Item>, io::Error> {
    let flavor = T::flavor() as i32;
    // No type `T` will be bigger than `c_int::MAX`!!
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let buffer_size = size_of::<T::Item>() as c_int * max_len as c_int;
    let mut buffer = (0..max_len)
        .map(|_| MaybeUninit::<T::Item>::uninit())
        .collect::<Vec<_>>();
    let buffer_ptr = buffer.as_mut_ptr().cast::<c_void>();

    let ret =
        syscall::cvt_positive(unsafe { proc_pidinfo(pid, flavor, 0, buffer_ptr, buffer_size) })?;
    // `ret` must be greater than 0 here, so no sign-loss
    #[allow(clippy::cast_sign_loss)]
    let actual_len = ret as usize / size_of::<T::Item>();
    buffer.truncate(actual_len);
    Ok(buffer
        .into_iter()
        .map(|x| unsafe { x.assume_init() })
        .collect())
}

/// Get the raw macOS `kinfo_proc` structure for `pid` via `sysctl(KERN_PROC_PID)`.
///
/// Unlike [`pidinfo`], this works for PID 0 (`kernel_task`) and does not require
/// root. Returns the raw [`KinfoProc`](crate::libproc::kinfo::KinfoProc); most
/// callers want the friendly [`kproc_info`] wrapper.
///
/// # Errors
///
/// Returns an error if `sysctl` fails (e.g. no process with the given `pid`).
pub fn kproc_info_raw(pid: i32) -> Result<KinfoProc, io::Error> {
    let mut mib: [c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // KinfoProc is a plain repr(C) struct of scalars/pointers; a zeroed value is a
    // valid initial state and sysctl overwrites it on success.
    let mut info = MaybeUninit::<KinfoProc>::zeroed();
    let mut size = mem::size_of::<KinfoProc>();

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::addr_of_mut!(info).cast::<c_void>(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No process found with pid {pid}"),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

/// Get process information for `pid` via `sysctl(KERN_PROC_PID)`.
///
/// Works for PID 0 (`kernel_task`) and other PIDs where [`pidinfo`] fails, and
/// does not require root for basic process information. Returns a friendly
/// [`KProcInfo`](crate::libproc::kinfo::KProcInfo); for the raw structure use
/// [`kproc_info_raw`].
///
/// # Errors
///
/// Returns an error if `sysctl` fails (e.g. no process with the given `pid`).
///
/// # Example
/// ```no_run
/// use mac_process::libproc::proc_pid::kproc_info;
/// if let Ok(info) = kproc_info(0) {
///     println!("PID 0 is {}", info.comm); // "kernel_task"
/// }
/// ```
pub fn kproc_info(pid: i32) -> Result<KProcInfo, io::Error> {
    kproc_info_raw(pid).map(|raw| KProcInfo::from(&raw))
}

/// Gets the path of the current working directory for the process with the provided pid.
///
/// # Errors
///
/// Currently, always returns an error as this is not implemented yet for macOS
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::pidcwd;
///
/// match pidcwd(1) {
///     Ok(cwd) => println!("The CWD of the process with pid=1 is '{}'", cwd.display()),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn pidcwd(_pid: pid_t) -> Result<PathBuf, String> {
    Err("pidcwd is not implemented for macos".into())
}

/// Gets the path of the current working directory for the current process.
///
/// Just wraps rust's `env::current_dir()` function so not so useful.
///
/// # Errors
///
/// Returns an Err if the current working directory value is invalid. Possible cases:
///   * Current directory does not exist.
///   * There are not enough permissions to access the current directory.
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::cwdself;
///
/// match cwdself() {
///     Ok(cwd) => println!("The CWD of the current process is '{}'", cwd.display()),
///     Err(err) => eprintln!("Error: {}", err)
/// }
/// ```
pub fn cwdself() -> Result<PathBuf, String> {
    env::current_dir().map_err(|e| e.to_string())
}

/// Determine if the current user ID of this process is root
///
/// # Examples
///
/// ```
/// use mac_process::libproc::proc_pid::am_root;
///
/// if am_root() {
///     println!("With great power comes great responsibility");
/// }
/// ```
#[must_use]
pub fn am_root() -> bool {
    // geteuid() is unstable still - wait for it or wrap this:
    // https://stackoverflow.com/questions/3214297/how-can-my-c-c-application-determine-if-the-root-user-is-executing-the-command
    unsafe { libc::getuid() == 0 }
}

/// Get the environment variables for a process using an undocumented syscall
pub fn proc_args2_raw(pid: pid_t) -> Result<Vec<u8>, io::Error> {
    // https://chromium.googlesource.com/crashpad/crashpad/+/refs/heads/master/util/posix/process_info_mac.cc
    let mut size_estimate: usize = 0;
    let mut size: usize;

    const PROC_ARGS2: c_int = 49;

    let mut mib: [c_int; _] = [libc::CTL_KERN, PROC_ARGS2, pid];
    let mut buf = vec![0u8; 0];

    loop {
        // Perform initial allocation
        syscall::cvt_nonnegative(unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size_estimate,
                std::ptr::null_mut(),
                0,
            )
        })?;
        size = size_estimate + 32;
        buf.resize(size, 0);
        // Perform actual retrieval
        match syscall::cvt_nonnegative(unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        }) {
            Ok(_) => {
                if size > size_estimate {
                    // Retry to prevent a race condition
                    continue;
                }
                buf.truncate(size);
                break;
            }
            // ENOMEM: oldlenp is too small
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        };
    }
    Ok(buf)
}

// run tests with 'cargo test -- --nocapture' to see the test output
#[cfg(test)]
// Don't worry about wrapping in tests
#[allow(clippy::cast_possible_wrap)]
mod test {
    use std::env;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;
    use std::process;

    use rustix::path::Arg;

    use crate::libproc::bsd_info::BSDInfo;
    use crate::libproc::file_info::ListFDs;
    use crate::libproc::task_info::TaskAllInfo;

    use super::am_root;
    use super::{ListThreads, libversion, listpidinfo, pidinfo, proc_args2_raw};
    use super::{cwdself, name, pidpath};
    use crate::libproc::task_info::TaskInfo;
    use crate::libproc::thread_info::ThreadInfo;
    use crate::libproc::work_queue_info::WorkQueueInfo;

    #[test]
    fn pidinfo_test() {
        let pid = process::id() as i32;

        match pidinfo::<BSDInfo>(pid, 0) {
            Ok(info) => assert_eq!(info.pbi_pid as i32, pid),
            Err(e) => panic!("Error retrieving BSDInfo: {}", e),
        }
    }

    #[test]
    fn pidinfo_kernel_task_test() {
        // PID = 0 is the kernel task - as is this will require running as root to pass
        if am_root() {
            let pid = 0;
            match pidinfo::<BSDInfo>(pid, 0) {
                Ok(info) => {
                    println!("BSDInfo: {info:?}");
                    assert_eq!(info.pbi_pid as i32, pid);
                }
                Err(e) => panic!("Error retrieving BSDInfo: {}", e),
            }
        }
    }

    #[test]
    fn taskinfo_test() {
        let pid = process::id() as i32;

        match pidinfo::<TaskInfo>(pid, 0) {
            Ok(info) => assert!(info.pti_virtual_size > 0),
            Err(e) => panic!("Error retrieving TaskInfo: {}", e),
        }
    }

    #[test]
    fn taskallinfo_test() {
        let pid = process::id() as i32;

        match pidinfo::<TaskAllInfo>(pid, 0) {
            Ok(info) => assert!(info.ptinfo.pti_virtual_size > 0),
            Err(e) => panic!("Error retrieving TaskAllInfo: {}", e),
        }
    }

    #[test]
    fn threadinfo_test() {
        let pid = process::id() as i32;

        // First get the task info to know how many threads there are
        let task_info = pidinfo::<TaskAllInfo>(pid, 0).expect("Failed to get TaskAllInfo");
        #[allow(clippy::cast_sign_loss)]
        let thread_count = task_info.ptinfo.pti_threadnum as usize;

        // Get the list of thread IDs
        let thread_ids =
            listpidinfo::<ListThreads>(pid, thread_count).expect("Failed to get thread list");
        assert!(!thread_ids.is_empty(), "Thread list should not be empty");

        // Use the first thread ID to get ThreadInfo
        let first_thread_id = thread_ids[0];
        match pidinfo::<ThreadInfo>(pid, first_thread_id) {
            Ok(info) => assert!(info.pth_run_state > 0),
            Err(e) => panic!("Error retrieving ThreadInfo: {}", e),
        }
    }

    #[test]
    fn workqueueinfo_test() {
        let pid = process::id() as i32;

        //  The "No such process" error (ESRCH) in this context actually means "no such
        //   work queue" - the process exists but doesn't have a GCD work queue.
        // A simple Rust test binary that doesn't use any GCD/libdispatch features never allocates
        // a work queue.
        // When proc_pidinfo with PROC_PIDWORKQUEUEINFO queries the kernel, it looks for the
        // process's workqueue structure. If none exists, it returns ESRCH.
        match pidinfo::<WorkQueueInfo>(pid, 0) {
            Ok(info) => assert!(info.pwq_nthreads > 0),
            Err(e) if e.raw_os_error().unwrap() == libc::ESRCH => {
                // Process has no work queue - this is valid
            }
            Err(e) => panic!("Error retrieving WorkQueueInfo: {}", e),
        }
    }

    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn listpidinfo_test() {
        let pid = process::id() as i32;

        if let Ok(info) = pidinfo::<TaskAllInfo>(pid, 0) {
            if let Ok(threads) = listpidinfo::<ListThreads>(pid, info.ptinfo.pti_threadnum as usize)
            {
                assert!(!threads.is_empty());
            }
            if let Ok(fds) = listpidinfo::<ListFDs>(pid, info.pbsd.pbi_nfiles as usize) {
                assert!(!fds.is_empty());
            }
        }
    }

    #[test]
    fn libversion_test() {
        libversion().expect("libversion() failed");
    }

    #[test]
    fn name_test() {
        if am_root() {
            assert!(
                &name(process::id() as i32)
                    .expect("Could not get the process name")
                    .as_str()
                    .unwrap()
                    .starts_with("libproc"),
                "Incorrect process name"
            );
        } else {
            println!("Cannot run 'name_test' on macos unless run as root");
        }
    }

    #[test]
    // This checks that it cannot find the path of the process with pid -1 and returns the correct error message
    fn pidpath_test_unknown_pid_test() {
        match pidpath(-1) {
            Ok(path) => panic!(
                "It found the path of process with ID = -1 (path = {}), that's not possible\n",
                path.display()
            ),
            Err(e) => assert!(e.raw_os_error().unwrap() == libc::ESRCH),
        }
    }

    #[test]
    // This checks that it cannot find the path of the process with pid 1
    fn pidpath_test() {
        assert_eq!(
            Path::new("/sbin/launchd"),
            pidpath(1).expect("pidpath() failed")
        );
    }

    // Pretty useless test as it uses the exact same code as the function - but I guess we
    // should check it can be called and returns the correct value
    #[test]
    fn cwd_self_test() {
        assert_eq!(
            env::current_dir().expect("Could not get current directory"),
            cwdself().expect("cwdself() failed")
        );
    }

    #[test]
    fn am_root_test() {
        if am_root() {
            println!("You are root");
        } else {
            println!("You are not root");
        }
    }

    #[test]
    fn env_test() {
        let pid = process::id() as i32;
        let env = proc_args2_raw(pid).expect("Failed to get environment");
        println!("Environment: {:?}", env);
        let what = OsString::from_vec(env);
        println!("Environment: {:?}", what);
    }
}
