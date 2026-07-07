//! Mach-specific functions.

use crate::libproc::bindings::{
    KERN_SUCCESS, au_asid_t, au_tid_t, audit_token_t, kern_return_t, mach_port_name_t,
};
use libc::{gid_t, pid_t, uid_t};
use mach2::task_info::TASK_AUDIT_TOKEN;
use std::{
    ffi::c_int,
    mem::{self, MaybeUninit},
};

unsafe extern "C" {
    // TODO: Replace with the one from `mach2::traps` when
    // https://github.com/JohnTitor/mach2/pull/71 is merged and released.
    fn task_name_for_pid(
        target_tport: mach_port_name_t,
        pid: c_int,
        tn: *mut mach_port_name_t,
    ) -> kern_return_t;
}

fn mach_task_name(pid: pid_t) -> Result<mach_port_name_t, system_error::Error> {
    let mut task_name = MaybeUninit::<mach_port_name_t>::uninit();

    // SAFETY:
    //  * `mach_task_self` is always safe to call: resolves a static variable;
    //  * `task_name` is mutable and of the correct type so the reference is
    //    aligned and points to initialized memory;
    //  * errors are checked for below;
    let res =
        unsafe { task_name_for_pid(mach2::traps::mach_task_self(), pid, task_name.as_mut_ptr()) };

    if res == KERN_SUCCESS as i32 {
        Ok(unsafe { task_name.assume_init() })
    } else {
        Err(system_error::Error::from_raw_kernel_error(res))
    }
}

fn mach_task_audit_token(
    task_name: mach_port_name_t,
) -> Result<audit_token_t, system_error::Error> {
    let mut audit_token = MaybeUninit::<audit_token_t>::zeroed();
    let mut audit_token_size =
        mem::size_of_val(&unsafe { audit_token.assume_init_ref() }.val) as u32;

    // SAFETY:
    //  * `task_name` is initialized;
    //  * `audit_token` is mutable and of the correct type so the reference
    //    is aligned and points to initialized memory, its type is in sync
    //    with `TASK_AUDIT_TOKEN` and `audit_token_size` is its size in bytes;
    //  * errors are checked for below;
    let res = unsafe {
        libc::task_info(
            task_name,
            TASK_AUDIT_TOKEN,
            audit_token.assume_init_mut().val.as_mut_ptr().cast(),
            &mut audit_token_size,
        )
    };

    if res == KERN_SUCCESS as i32 {
        Ok(unsafe { audit_token.assume_init() })
    } else {
        Err(system_error::Error::from_raw_kernel_error(res))
    }
}

/// Converts a PID to an audit token.
pub fn audit_token_from_pid(pid: pid_t) -> Result<audit_token_t, system_error::Error> {
    let task_name = mach_task_name(pid)?;
    mach_task_audit_token(task_name)
}

#[link(name = "bsm", kind = "dylib")]
unsafe extern "C" {
    /// Extract information from an [`audit_token_t`], used to identify Mach tasks and senders
    /// of Mach messages as subjects to the audit system. `audit_tokent_to_au32()` is the only
    /// method that should be used to parse an `audit_token_t`, since its internal representation
    /// may change over time. A pointer parameter may be `NULL` if that information is not needed.
    /// `audit_token_to_au32()` has been deprecated because the terminal ID information is no
    /// longer saved in this token. The last parameter is actually the process ID version. The
    /// API calls [`audit_token_to_auid()`], [`audit_token_to_euid()`], [`audit_token_to_ruid()`],
    /// [`audit_token_to_rgid()`], [`audit_token_to_pid()`], [`audit_token_to_asid()`], and/or
    /// [`audit_token_to_pidversion()`] should be used instead.
    ///
    /// Note: **this function has been deprecated by Apple in an unknown version**.
    ///
    /// - `atoken`: the audit token containing the desired information
    /// - `auidp`: Pointer to a `uid_t`; on return will be set to the task or sender's audit user ID
    /// - `euidp`: Pointer to a `uid_t`; on return will be set to the task or sender's effective
    ///   user ID
    /// - `egidp`: Pointer to a `gid_t`; on return will be set to the task or sender's effective
    ///   group ID
    /// - `ruidp`: Pointer to a `uid_t`; on return will be set to the task or sender's real user ID
    /// - `rgidp`: Pointer to a `gid_t`; on return will be set to the task or sender's real group ID
    /// - `pidp`: Pointer to a `pid_t`; on return will be set to the task or sender's process ID
    /// - `asidp`: Pointer to an `au_asid_t`; on return will be set to the task or sender's audit
    ///   session ID
    /// - `tidp`: Pointer to an `au_tid_t`; on return will be set to the process ID version and NOT
    ///   THE SENDER'S TERMINAL ID.
    ///
    /// IMPORTANT: In Apple's `bsm-8`, these are marked `__APPLE_API_PRIVATE`.
    pub fn audit_token_to_au32(
        atoken: audit_token_t,
        auidp: *mut uid_t,
        euidp: *mut uid_t,
        egidp: *mut gid_t,
        ruidp: *mut uid_t,
        rgidp: *mut gid_t,
        pidp: *mut pid_t,
        asidp: *mut au_asid_t,
        tidp: *mut au_tid_t,
    );

    /// Extract the audit user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The audit user ID extracted from the Mach audit token.
    pub fn audit_token_to_auid(atoken: audit_token_t) -> uid_t;

    /// Extract the effective user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The effective user ID extracted from the Mach audit token.
    pub fn audit_token_to_euid(atoken: audit_token_t) -> uid_t;

    /// Extract the effective group ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The effective group ID extracted from the Mach audit token.
    pub fn audit_token_to_egid(atoken: audit_token_t) -> gid_t;

    /// Extract the real user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The real user ID extracted from the Mach audit token.
    pub fn audit_token_to_ruid(atoken: audit_token_t) -> uid_t;

    /// Extract the real group ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The real group ID extracted from the Mach audit token.
    pub fn audit_token_to_rgid(atoken: audit_token_t) -> gid_t;

    /// Extract the process ID from an `audit_token_t`, used to identify Mach tasks and senders
    /// of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The process ID extracted from the Mach audit token.
    pub fn audit_token_to_pid(atoken: audit_token_t) -> pid_t;

    /// Extract the audit session ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The audit session ID extracted from the Mach audit token.
    pub fn audit_token_to_asid(atoken: audit_token_t) -> au_asid_t;

    /// Extract the process ID version from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The process ID version extracted from the Mach audit token.
    pub fn audit_token_to_pidversion(atoken: audit_token_t) -> c_int;
}
