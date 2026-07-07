use std::time::{Duration, SystemTime};

/// Converts a tuple of (seconds, nanoseconds) since the Unix epoch to a `SystemTime`.
///
/// This handles negative seconds (times before the Unix epoch) and truncate seconds that are out of bounds.
pub(crate) fn system_time_from_unix(secs: i64, nsecs: i64) -> SystemTime {
    let nsecs = nsecs.clamp(0, 999_999_999) as u32;
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}
