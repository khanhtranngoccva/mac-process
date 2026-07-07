//! Types for macOS-specific information about a process' threads
use crate::libproc::proc_pid::{PIDInfo, PidInfoFlavor};
pub use crate::libproc::bindings::proc_threadinfo as ThreadInfo;

impl PIDInfo for ThreadInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::ThreadInfo
    }
}
