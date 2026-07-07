//! Types for macOS-specific information about a process' virtual memory regions
pub use crate::libproc::bindings::proc_regioninfo as RegionInfo;
pub use crate::libproc::bindings::proc_regionwithpathinfo as RegionWithPathInfo;
use crate::libproc::proc_pid::{PIDInfo, PidInfoFlavor};

impl PIDInfo for RegionInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::RegionInfo
    }
}

impl PIDInfo for RegionWithPathInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::RegionPathInfo
    }
}
