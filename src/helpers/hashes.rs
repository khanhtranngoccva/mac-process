use digest::Digest;
use md5::Md5;
use sha2::Sha256;
use std::io::{self, Read};

pub(crate) fn compute_md5<R: Read>(mut reader: R) -> Result<[u8; 16], io::Error> {
    let mut hasher = Md5::new();
    let mut buffer = [0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn compute_sha256<R: Read>(mut reader: R) -> Result<[u8; 32], io::Error> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}
