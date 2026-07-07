//! Types for macOS-specific BSD information
pub use crate::libproc::bindings::proc_bsdinfo as BSDInfo;
use crate::libproc::proc_pid::{PIDInfo, PidInfoFlavor};

impl PIDInfo for BSDInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::TBSDInfo
    }
}
