//! High-level types for parsing environment variables and arguments of a process.

use crate::libproc::args::ProcArgs2;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};

/// Represents the arguments and environment variables of a process.
#[derive(Debug, Clone)]
pub struct ProcessArgInfo {
    /// The path to the executable.
    pub exe_path: PathBuf,
    /// The arguments passed to the process.
    pub args: Vec<OsString>,
    /// The environment variables passed to the process.
    pub environment: HashMap<OsString, OsString>,
    /// The Apple specific variables of the process.
    pub apple_variables: HashMap<OsString, OsString>,
}

fn split_eq(s: &OsStr) -> (OsString, OsString) {
    let d = s.as_bytes();
    let eq_index = match d.iter().position(|&b| b == b'=') {
        Some(index) if index < d.len() - 1 => index,
        _ => return (s.to_os_string(), OsString::new()),
    };
    (
        OsString::from_vec(d[..eq_index].to_vec()),
        OsString::from_vec(d[eq_index + 1..].to_vec()),
    )
}

impl ProcessArgInfo {
    /// Parses the arguments and environment variables of a process from a raw ProcArgs2 structure.
    pub fn parse(raw: &ProcArgs2) -> Self {
        let environment = raw
            .envp
            .iter()
            .map(|s| split_eq(s))
            .collect::<HashMap<OsString, OsString>>();
        let apple_variables = raw
            .applev
            .iter()
            .map(|s| split_eq(s))
            .collect::<HashMap<OsString, OsString>>();
        Self {
            exe_path: raw.exe_path.clone(),
            args: raw.argv.clone(),
            environment,
            apple_variables,
        }
    }
}

impl From<ProcArgs2> for ProcessArgInfo {
    fn from(args: ProcArgs2) -> Self {
        ProcessArgInfo::parse(&args)
    }
}
