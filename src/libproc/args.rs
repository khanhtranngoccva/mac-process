//! Types for parsing environment variables and arguments of a process.
use std::{
    ffi::OsString,
    io::{self},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

#[derive(Debug, Clone)]
/// Represents the arguments and environment variables of a process as stored in the procargs2 structure.
pub struct ProcArgs2 {
    /// The number of arguments passed to the process.
    pub argc: u32,
    /// The path to the executable.
    pub exe_path: PathBuf,
    /// The arguments passed to the process.
    pub argv: Vec<OsString>,
    /// The environment variables passed to the process.
    pub envp: Vec<OsString>,
    /// The Apple specific variables of the process.
    pub applev: Vec<OsString>,
}

impl ProcArgs2 {
    /// Parses the procargs2 data from a raw buffer.
    pub fn from_raw(raw: &[u8]) -> Result<Self, io::Error> {
        // State: start of argc block
        let (argc_buf, raw) = raw.split_first_chunk::<4>().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "procargs2 buffer too small to hold argc",
            )
        })?;
        let argc: u32 = i32::from_ne_bytes(*argc_buf).try_into().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid argc (cannot convert to positive): {}", e),
            )
        })?;

        // argc block + envp block form a larger null-delimited block, demarcated by the argc count. Must ensure that the argc + envp block is non-empty; otherwise, we could parse the wrong blocks
        if argc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "procargs2 argc is 0",
            ));
        }

        // State: end of argc block, start of exe_path block
        let null_position = raw.iter().position(|&b| b == 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "null byte not found in procargs2 buffer for executable path",
            )
        })?;
        let (exe_path_raw, raw) = raw.split_at(null_position);
        let exe_path = PathBuf::from(OsString::from_vec(exe_path_raw.to_vec()));
        let non_null_position = raw.iter().position(|&b| b != 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no non-null byte found in procargs2 buffer for start of argv",
            )
        })?;
        let (_null_portion, mut raw) = raw.split_at(non_null_position);

        // State: End of exe_path block, start of argv + envp block
        let mut argv_envp_items = vec![];
        loop {
            let null_position = raw.iter().position(|&b| b == 0).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "null byte not found in procargs2 buffer for argv/envp item",
                )
            })?;
            let argv_envp_item_raw;
            (argv_envp_item_raw, raw) = raw.split_at(null_position);
            argv_envp_items.push(OsString::from_vec(argv_envp_item_raw.to_vec()));
            let second_byte = raw.get(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "procargs2 missing byte")
            })?;
            if *second_byte == 0 {
                break;
            }
            raw = &raw[1..];
        }
        let (argv, envp) = argv_envp_items
            .split_at_checked(argc as usize)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "procargs2 argv is too short: expected {} items, got {}",
                        argc,
                        argv_envp_items.len()
                    ),
                )
            })?;
        let argv = argv.to_vec();
        let envp = envp.to_vec();
        let non_null_position = match raw.iter().position(|&b| b != 0) {
            Some(position) => position,
            None => {
                // applev is the last block, and it's OK if no variables are present
                return Ok(Self {
                    argc,
                    exe_path,
                    argv,
                    envp,
                    applev: vec![],
                });
            }
        };
        let (_null_portion, mut raw) = raw.split_at(non_null_position);
        // State: end of envp block, start of applev block
        let mut applev_items = vec![];
        loop {
            let null_position = raw.iter().position(|&b| b == 0).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "null byte not found in procargs2 buffer for applev item",
                )
            })?;
            let _applev_item_raw;
            (_applev_item_raw, raw) = raw.split_at(null_position);
            applev_items.push(OsString::from_vec(_applev_item_raw.to_vec()));
            let non_null_position = match raw.iter().position(|&b| b != 0) {
                Some(position) => position,
                None => {
                    return Ok(Self {
                        argc,
                        exe_path,
                        argv,
                        envp,
                        applev: applev_items,
                    });
                }
            };
            let _null_portion;
            (_null_portion, raw) = raw.split_at(non_null_position);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::process;

    #[test]
    fn test_from_raw() {
        let raw = crate::libproc::proc_pid::proc_args2_raw(process::id() as i32).unwrap();
        let args = ProcArgs2::from_raw(&raw).unwrap();
        println!("args: {:?}", args);
    }
}
