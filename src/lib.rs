//! A hybrid library for querying process information on macOS
//!
//! This library is a modification of https://github.com/andrewdavidmackenzie/libproc-rs with a few modifications:
//! - Supports a higher-level construct with the help of Mach functions, libproc functions, and the kqueue API - the [`ProcessMonitor`] monitor that yields [`Process`] objects, which is a shared, almost-race-free handle to a live process. To avoid race conditions due to PID reuse, dead processes cannot be queried (if they happen to be queried, the results are ignored).
//! - All errors are converted to [`std::io::Error`], and certain items in low-level libraries are also parsed into Rust types.
//! - Caching of certain immutable fields is supported - this is useful when a user needs to query the same process multiple times.
//! - Supports opening the main executable for checking its contents (e.g. hashes).
//! - Focuses mainly on macOS-specific functionality, while other OSes are not supported (Linux users should use procfs). 
//!
//! # Notes
//! - Race free handles are theoretically not possible even with checking audit tokens and kqueue. However, such chances are very unlikely - an attacking process must cycle the whole u32 numeric space in a very brief timeframe, in which kqueue has not marked the process as dead.
//!
#![warn(missing_docs)]
#![cfg(target_os = "macos")]
mod helpers;
pub mod libproc;
pub mod monitor;

// Re-exports of most important high-level constructs
pub use monitor::{Process, ProcessMonitor};
pub use system_error::Error as SystemError;
