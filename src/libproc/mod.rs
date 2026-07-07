//! Mid-level functions that wrap the libproc API.
pub mod bsd_info;
pub mod file_info;
pub mod kinfo;
pub mod kmesg_buffer;
pub mod net_info;
pub mod pid_rusage;
pub mod proc_pid;
pub mod processes;
pub mod region_info;
mod sys;
pub mod task_info;
pub mod thread_info;
pub mod work_queue_info;
pub mod mach;

#[allow(warnings, missing_docs)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/osx_libproc_bindings.rs"));
}
