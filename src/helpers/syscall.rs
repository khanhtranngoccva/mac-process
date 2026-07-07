use std::io;

/// Converts Unix return integers to Result using the *value <= 0 means error is in `errno`*  convention.
/// Non-error values are `Ok`-wrapped.
pub(crate) fn cvt_positive<T: Into<i64> + Copy>(t: T) -> io::Result<T> {
    if t.into() <= 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

/// Converts Unix return integers to Result using the *value < 0 means error is in `errno`*  convention (which treats 0 as a success value).
/// Non-error values are `Ok`-wrapped.
pub(crate) fn cvt_nonnegative<T: Into<i64> + Copy>(t: T) -> io::Result<T> {
    if t.into() < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}
