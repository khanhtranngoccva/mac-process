//! A region iterator for a process.
use super::Process;
use crate::monitor::regions::{Region, RegionWithPath};
use std::io;

/// An iterator that yields information about virtual memory regions in a process.
pub struct RegionIterator<'a> {
    seek: u64,
    process: &'a Process,
    any_errors: bool,
}

impl<'a> RegionIterator<'a> {
    pub(crate) fn new(process: &'a Process) -> Self {
        Self {
            seek: 0,
            process,
            any_errors: false,
        }
    }
}

impl<'a> Iterator for RegionIterator<'a> {
    type Item = Result<Region, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.any_errors {
            return None;
        }
        match self.process.region_at(self.seek) {
            Ok(region_info) => {
                self.seek = region_info.address() + region_info.size();
                Some(Ok(region_info))
            }
            Err(e)
                if e.raw_os_error() == Some(libc::ESRCH)
                    || e.raw_os_error() == Some(libc::EINVAL) =>
            {
                None
            }
            Err(e) => {
                self.any_errors = true;
                Some(Err(e))
            }
        }
    }
}

/// An iterator that yields information about virtual memory regions with path information in a process.
pub struct RegionWithPathIterator<'a> {
    seek: u64,
    process: &'a Process,
    any_errors: bool,
}

impl<'a> RegionWithPathIterator<'a> {
    pub(crate) fn new(process: &'a Process) -> Self {
        Self {
            seek: 0,
            process,
            any_errors: false,
        }
    }
}

impl<'a> Iterator for RegionWithPathIterator<'a> {
    type Item = Result<RegionWithPath, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.any_errors {
            return None;
        }
        match self.process.region_with_path_at(self.seek) {
            Ok(region_info) => {
                self.seek = region_info.region().address() + region_info.region().size();
                Some(Ok(region_info))
            }
            Err(e)
                if e.raw_os_error() == Some(libc::ESRCH)
                    || e.raw_os_error() == Some(libc::EINVAL) =>
            {
                None
            }
            Err(e) => {
                self.any_errors = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ProcessMonitor;
    use rustix::process::Pid;

    #[test]
    fn test_region_info_iterator() {
        let monitor = ProcessMonitor::new().unwrap();
        let mut test_process = crate::monitor::spawn_example_process();
        let test_pid =
            Pid::from_raw(test_process.id() as i32).expect("test process should have a valid PID");
        let process = monitor.get(test_pid).unwrap();
        let iterator = process.region_iterator();

        for region in iterator {
            let region = region.expect("region should be valid");
            println!("region: {:?}", region);
        }
        test_process.kill().expect("test process should be killed");
        test_process.wait().expect("test process should be waited");
    }

    #[test]
    fn test_region_info_with_path_iterator() {
        let monitor = ProcessMonitor::new().unwrap();
        let mut test_process = crate::monitor::spawn_example_process();
        let test_pid =
            Pid::from_raw(test_process.id() as i32).expect("test process should have a valid PID");
        let process = monitor.get(test_pid).unwrap();
        let iterator = process.region_with_path_iterator();

        for region in iterator {
            let region = region.expect("region should be valid");
            println!("region: {:?}", region);
        }
        test_process.kill().expect("test process should be killed");
        test_process.wait().expect("test process should be waited");
    }
}
