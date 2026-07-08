//! High level audit token module that more stably identifies a process/task
use crate::libproc::{
    bindings::{au_asid_t, audit_token_t},
    mach,
};
use rustix::{
    fs::{Gid, Uid},
    process::Pid,
};
use std::{
    hash::{Hash, Hasher},
    num::TryFromIntError,
};

/// The audit token is an opaque token which identifies Mach tasks and senders of Mach messages
/// as subjects to the BSM audit system.  Only the appropriate BSM library routines should
/// be used to interpret the contents of the audit token as the representation of the subject
/// identity within the token may change over time.
#[derive(Debug, Clone, Copy)]
pub struct AuditToken {
    raw: audit_token_t,
}

impl PartialEq for AuditToken {
    fn eq(&self, other: &Self) -> bool {
        self.raw.val == other.raw.val
    }
}

impl Eq for AuditToken {}

impl Hash for AuditToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.val.hash(state);
    }
}

impl AuditToken {
    /// Converts a PID to an audit token.
    pub fn from_pid(pid: Pid) -> Result<Self, system_error::Error> {
        let audit_token = mach::audit_token_from_pid(pid.as_raw_pid())?;
        Ok(AuditToken { raw: audit_token })
    }

    /// Raw underlying audit token.
    #[inline]
    pub fn raw_token(&self) -> &audit_token_t {
        &self.raw
    }

    /// The audit user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn auid(&self) -> Uid {
        // Safety: The audit_token_t is owned by self.
        unsafe { Uid::from_raw_unchecked(mach::audit_token_to_auid(self.raw)) }
    }

    /// The effective user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn euid(&self) -> Uid {
        // Safety: The audit_token_t is owned by self.
        unsafe { Uid::from_raw_unchecked(mach::audit_token_to_euid(self.raw)) }
    }

    /// The effective group ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn egid(&self) -> Gid {
        // Safety: The audit_token_t is owned by self.
        unsafe { Gid::from_raw_unchecked(mach::audit_token_to_egid(self.raw)) }
    }

    /// The real user ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn ruid(&self) -> Uid {
        // Safety: The audit_token_t is owned by self.
        unsafe { Uid::from_raw_unchecked(mach::audit_token_to_ruid(self.raw)) }
    }

    /// The real group ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn rgid(&self) -> Gid {
        // Safety: The audit_token_t is owned by self.
        unsafe { Gid::from_raw_unchecked(mach::audit_token_to_rgid(self.raw)) }
    }

    /// The process ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn pid(&self) -> Result<u32, TryFromIntError> {
        // Safety: The audit_token_t is owned by self.
        unsafe { mach::audit_token_to_pid(self.raw).try_into() }
    }

    /// The audit session ID.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn asid(&self) -> au_asid_t {
        // Safety: The audit_token_t is owned by self.
        unsafe { mach::audit_token_to_asid(self.raw) }
    }

    /// The process ID version.
    ///
    /// **NOTE**: Used to identify Mach tasks and senders of Mach messages as subjects of the audit system.
    #[inline(always)]
    pub fn pidversion(&self) -> i32 {
        // Safety: The audit_token_t is owned by self.
        unsafe { mach::audit_token_to_pidversion(self.raw) }
    }
}
