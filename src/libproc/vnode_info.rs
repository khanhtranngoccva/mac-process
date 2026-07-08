//! Types for macOS-specific information about a process' vnode path information (containing the current working directory and root directory)
pub use crate::libproc::bindings::proc_vnodepathinfo as ProcessVnodePathInfo;
use crate::libproc::proc_pid::{PIDInfo, PidInfoFlavor};

impl PIDInfo for ProcessVnodePathInfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::VNodePathInfo
    }
}
