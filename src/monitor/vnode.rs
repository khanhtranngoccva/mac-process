//! High-level types and functions for vnode information
use crate::{
    helpers::time,
    libproc::{
        bindings::{proc_vnodepathinfo, vinfo_stat, vnode_info, vnode_info_path},
        file_info::ProcFDType,
    },
};
use core::slice;
use ref_cast::RefCast;
use rustix::fs::{Dev, FileType, Fsid, Gid, Mode, OFlags, RawMode, Uid};
use std::{
    ffi::{CStr, OsStr},
    fmt::Debug,
    io,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::Path,
    time::SystemTime,
};

/// Trait for types that can be opened as a file.
pub trait Openable {
    /// Returns the identity of the file (combination of device and inode)
    fn identity(&self) -> (Dev, u64);

    /// Opens the file using the identity from `/.vol` and returns an OwnedFd descriptor.
    fn open(&self, flags: OFlags) -> Result<OwnedFd, io::Error> {
        let (dev, ino) = self.identity();
        let stable_path = Path::new("/.vol")
            .join(dev.to_string())
            .join(ino.to_string());
        let owned_fd = rustix::fs::open(stable_path, flags, Mode::empty())?;
        Ok(owned_fd)
    }
}

/// A high-level representation of a vnode stat returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct VnodeStat {
    raw: vinfo_stat,
}

impl VnodeStat {
    /// Creates a new vnode stat from a raw vnode stat info
    pub fn from_raw(raw: vinfo_stat) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &vinfo_stat {
        &self.raw
    }

    /// Returns the device number of the vnode stat
    pub fn dev(&self) -> Dev {
        self.raw.vst_dev as Dev
    }

    /// Returns the raw mode of the vnode stat (combination of mode and file type)
    pub fn raw_mode(&self) -> RawMode {
        self.raw.vst_mode
    }

    /// Returns the file type of the vnode stat
    pub fn file_type(&self) -> FileType {
        FileType::from_raw_mode(self.raw.vst_mode)
    }

    /// Returns the access permissions of the vnode stat
    pub fn mode(&self) -> Mode {
        Mode::from_raw_mode(self.raw.vst_mode)
    }

    /// Returns the number of links to the vnode stat
    pub fn nlink(&self) -> u16 {
        self.raw.vst_nlink
    }

    /// Returns the inode number of the vnode stat
    pub fn ino(&self) -> u64 {
        self.raw.vst_ino
    }

    /// Returns the user ID of the vnode stat
    pub fn uid(&self) -> Uid {
        Uid::from_raw_unchecked(self.raw.vst_uid)
    }

    /// Returns the group ID of the vnode stat
    pub fn gid(&self) -> Gid {
        Gid::from_raw_unchecked(self.raw.vst_gid)
    }

    /// Returns the access time of the vnode stat
    pub fn atime(&self) -> SystemTime {
        time::system_time_from_unix(self.raw.vst_atime, self.raw.vst_atimensec)
    }

    /// Returns the modification time of the vnode stat
    pub fn mtime(&self) -> SystemTime {
        time::system_time_from_unix(self.raw.vst_mtime, self.raw.vst_mtimensec)
    }

    /// Returns the change time of the vnode stat
    pub fn ctime(&self) -> SystemTime {
        time::system_time_from_unix(self.raw.vst_ctime, self.raw.vst_ctimensec)
    }

    /// Returns the birth time of the vnode stat
    pub fn birthtime(&self) -> SystemTime {
        time::system_time_from_unix(self.raw.vst_birthtime, self.raw.vst_birthtimensec)
    }

    /// Returns the size of the vnode stat
    pub fn size(&self) -> u64 {
        self.raw.vst_size.max(0) as u64
    }

    /// Returns the number of blocks of the vnode stat
    pub fn blocks(&self) -> u64 {
        self.raw.vst_blocks.max(0) as u64
    }

    /// Returns the block size of the vnode stat
    pub fn blksize(&self) -> u32 {
        self.raw.vst_blksize.max(0) as u32
    }

    /// Returns the flags of the vnode stat
    pub fn flags(&self) -> u32 {
        self.raw.vst_flags
    }

    /// Returns the node generation number of the vnode stat
    pub fn generation(&self) -> u32 {
        self.raw.vst_gen
    }

    /// Returns the device number of the vnode stat
    pub fn rdev(&self) -> Dev {
        self.raw.vst_rdev as Dev
    }

    /// Returns the spare fields of the vnode stat
    pub fn spare(&self) -> [i64; 2] {
        self.raw.vst_qspare
    }
}

impl Debug for VnodeStat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VnodeStat")
            .field("dev", &self.dev())
            .field("mode", &self.mode())
            .field("nlink", &self.nlink())
            .field("ino", &self.ino())
            .field("uid", &self.uid())
            .field("gid", &self.gid())
            .field("atime", &self.atime())
            .field("mtime", &self.mtime())
            .field("ctime", &self.ctime())
            .field("birthtime", &self.birthtime())
            .field("size", &self.size())
            .field("blocks", &self.blocks())
            .field("blksize", &self.blksize())
            .field("flags", &self.flags())
            .field("generation", &self.generation())
            .field("rdev", &self.rdev())
            .finish()
    }
}

impl Openable for VnodeStat {
    fn identity(&self) -> (Dev, u64) {
        (self.dev(), self.ino())
    }
}

/// A high-level representation of a vnode returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct Vnode {
    raw: vnode_info,
}

impl Vnode {
    /// Creates a new vnode from a raw vnode info
    pub fn from_raw(raw: vnode_info) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &vnode_info {
        &self.raw
    }

    /// Returns the stat of the vnode
    pub fn stat(&self) -> VnodeStat {
        VnodeStat::from_raw(self.raw.vi_stat)
    }

    /// Returns the vnode type
    pub fn node_type(&self) -> ProcFDType {
        ProcFDType::from(self.raw.vi_type as u32)
    }

    /// Returns the pad of the vnode
    pub fn pad(&self) -> i32 {
        self.raw.vi_pad
    }

    /// Returns the filesystem ID of the vnode
    pub fn fsid(&self) -> Fsid {
        // SAFETY: fsid_t is a 2-element array of i32
        unsafe { std::mem::transmute(self.raw.vi_fsid) }
    }
}

impl Debug for Vnode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vnode")
            .field("stat", &self.stat())
            .field("node_type", &self.node_type())
            .field("pad", &self.pad())
            .field("fsid", &self.fsid())
            .finish()
    }
}

impl Openable for Vnode {
    fn identity(&self) -> (Dev, u64) {
        self.stat().identity()
    }
}

/// A high-level representation of a vnode path returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct VnodeWithPath {
    raw: vnode_info_path,
}

impl VnodeWithPath {
    /// Creates a new vnode path from a raw vnode path info
    pub fn from_raw(raw: vnode_info_path) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &vnode_info_path {
        &self.raw
    }

    /// Returns the vnode
    pub fn vnode(&self) -> &Vnode {
        Vnode::ref_cast(&self.raw.vip_vi)
    }

    /// Returns the path of the vnode
    pub fn path(&self) -> &Path {
        let i8_slice = self.raw.vip_path.as_slice();
        let u8_slice =
            unsafe { slice::from_raw_parts(i8_slice.as_ptr() as *const u8, i8_slice.len()) };
        let bytes = match CStr::from_bytes_until_nul(u8_slice) {
            Ok(c_str) => c_str.to_bytes(),
            Err(_) => u8_slice,
        };
        let osstr = OsStr::from_bytes(bytes);
        Path::new(osstr)
    }
}

impl Debug for VnodeWithPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VnodeWithPath")
            .field("vnode", &self.vnode())
            .field("path", &self.path())
            .finish()
    }
}

impl Openable for VnodeWithPath {
    fn identity(&self) -> (Dev, u64) {
        self.vnode().identity()
    }
}

/// A high-level representation of path states of a process returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct ProcessVnodePaths {
    raw: proc_vnodepathinfo,
}

impl ProcessVnodePaths {
    /// Creates a new process vnode paths structure from a raw process vnode path info
    pub fn from_raw(raw: proc_vnodepathinfo) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &proc_vnodepathinfo {
        &self.raw
    }

    /// Returns the current working directory of the process
    pub fn cwd(&self) -> &VnodeWithPath {
        VnodeWithPath::ref_cast(&self.raw.pvi_cdir)
    }

    /// Returns the root directory of the process
    pub fn root(&self) -> &VnodeWithPath {
        VnodeWithPath::ref_cast(&self.raw.pvi_rdir)
    }
}
