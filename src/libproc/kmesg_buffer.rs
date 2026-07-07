//! Function for getting messages from the kernel message buffer
use crate::libproc::bindings::{MAXBSIZE as MAX_MSG_BSIZE, proc_kmsgbuf};
use libc::c_void;
use std::io;
use std::str;

/// Read messages from the kernel message buffer
///
/// Entries are in the format:
/// faclev,seqnum,timestamp[optional, ...];message\n
///  TAGNAME=value (0 or more Tags)
/// See <http://opensource.apple.com//source/system_cmds/system_cmds-336.6/dmesg.tproj/dmesg.c>
///
/// # Errors
///
/// An `Err` will be returned if `/dev/kmsg` device cannot be read
pub fn kmsgbuf() -> Result<String, io::Error> {
    let mut message_buffer: Vec<u8> = Vec::with_capacity(MAX_MSG_BSIZE as _);
    let buffer_ptr = message_buffer.as_mut_ptr().cast::<c_void>();
    let ret: i32;

    unsafe {
        // This assumes that MAX_MSG_BSIZE < u32::MAX - but compile time asserts are experimental
        #[allow(clippy::cast_possible_truncation)]
        let buffersize = message_buffer.capacity() as u32;
        ret = proc_kmsgbuf(buffer_ptr, buffersize);
        if ret > 0 {
            // `ret` cannot be negative here - so cannot lose the sign
            #[allow(clippy::cast_sign_loss)]
            message_buffer.set_len(ret as usize - 1);
        }
    }

    if message_buffer.is_empty() {
        // Treat kmsgbuf as a file
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Could not read kernel message buffer",
        ))
    } else {
        let msg = str::from_utf8(&message_buffer)
            .map_err(|_| io::Error::other("Could not convert kernel message buffer from utf8"))?
            .parse()
            .map_err(|_| io::Error::other("Could not parse kernel message"))?;
        Ok(msg)
    }
}

#[cfg(test)]
mod test {
    use super::kmsgbuf;
    use crate::libproc::proc_pid::am_root;

    #[test]
    fn kmessage_buffer_test() {
        if am_root() {
            match kmsgbuf() {
                Ok(_) => {}
                Err(message) => panic!("{}", message),
            }
        } else {
            println!("test skipped as it needs to be run as root");
        }
    }
}
