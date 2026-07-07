//! High-level types and functions for memory region information
use crate::{
    libproc::region_info::{RegionInfo, RegionWithPathInfo},
    monitor::vnode::VnodeWithPath,
};
use ref_cast::RefCast;
use std::fmt::Debug;

/// A high-level representation of a memory region returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct Region {
    raw: RegionInfo,
}

impl Region {
    /// Creates a new region from a raw region info
    pub fn from_raw(raw: RegionInfo) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &RegionInfo {
        &self.raw
    }

    /// Returns the protection of the region
    pub fn protection(&self) -> u32 {
        self.raw.pri_protection
    }

    /// Returns the maximum protection of the region
    pub fn max_protection(&self) -> u32 {
        self.raw.pri_max_protection
    }

    /// Returns the inheritance of the region
    pub fn inheritance(&self) -> u32 {
        self.raw.pri_inheritance
    }

    /// Returns the flags of the region
    pub fn flags(&self) -> u32 {
        self.raw.pri_flags
    }

    /// Returns the offset of the region
    pub fn offset(&self) -> u64 {
        self.raw.pri_offset
    }

    /// Returns the behavior of the region
    pub fn behavior(&self) -> u32 {
        self.raw.pri_behavior
    }

    /// Returns the user wired count of the region
    pub fn user_wired_count(&self) -> u32 {
        self.raw.pri_user_wired_count
    }

    /// Returns the user tag of the region
    pub fn user_tag(&self) -> u32 {
        self.raw.pri_user_tag
    }

    /// Returns the pages resident of the region
    pub fn pages_resident(&self) -> u32 {
        self.raw.pri_pages_resident
    }

    /// Returns the pages shared now private of the region
    pub fn pages_shared_now_private(&self) -> u32 {
        self.raw.pri_pages_shared_now_private
    }

    /// Returns the pages swapped out of the region
    pub fn pages_swapped_out(&self) -> u32 {
        self.raw.pri_pages_swapped_out
    }

    /// Returns the pages dirtied of the region
    pub fn pages_dirtied(&self) -> u32 {
        self.raw.pri_pages_dirtied
    }

    /// Returns the reference count of the region
    pub fn ref_count(&self) -> u32 {
        self.raw.pri_ref_count
    }

    /// Returns the shadow depth of the region
    pub fn shadow_depth(&self) -> u32 {
        self.raw.pri_shadow_depth
    }

    /// Returns the share mode of the region
    pub fn share_mode(&self) -> u32 {
        self.raw.pri_share_mode
    }

    /// Returns the private pages resident of the region
    pub fn private_pages_resident(&self) -> u32 {
        self.raw.pri_private_pages_resident
    }

    /// Returns the shared pages resident of the region
    pub fn shared_pages_resident(&self) -> u32 {
        self.raw.pri_shared_pages_resident
    }

    /// Returns the object ID of the region
    pub fn obj_id(&self) -> u32 {
        self.raw.pri_obj_id
    }

    /// Returns the depth of the region
    pub fn depth(&self) -> u32 {
        self.raw.pri_depth
    }

    /// Returns the address of the region
    pub fn address(&self) -> u64 {
        self.raw.pri_address
    }

    /// Returns the size of the region
    pub fn size(&self) -> u64 {
        self.raw.pri_size
    }
}

impl From<RegionInfo> for Region {
    fn from(raw: RegionInfo) -> Self {
        Self { raw }
    }
}

impl Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("protection", &self.protection())
            .field("max_protection", &self.max_protection())
            .field("inheritance", &self.inheritance())
            .field("flags", &self.flags())
            .field("offset", &self.offset())
            .field("behavior", &self.behavior())
            .field("user_wired_count", &self.user_wired_count())
            .field("user_tag", &self.user_tag())
            .field("pages_resident", &self.pages_resident())
            .field("pages_shared_now_private", &self.pages_shared_now_private())
            .field("pages_swapped_out", &self.pages_swapped_out())
            .field("pages_dirtied", &self.pages_dirtied())
            .field("ref_count", &self.ref_count())
            .field("shadow_depth", &self.shadow_depth())
            .field("share_mode", &self.share_mode())
            .field("private_pages_resident", &self.private_pages_resident())
            .field("shared_pages_resident", &self.shared_pages_resident())
            .field("obj_id", &self.obj_id())
            .field("depth", &self.depth())
            .field("address", &self.address())
            .field("size", &self.size())
            .finish()
    }
}

/// A high-level representation of a memory region with path returned by `libproc`
#[repr(transparent)]
#[derive(RefCast, Clone, Copy)]
pub struct RegionWithPath {
    raw: RegionWithPathInfo,
}

impl RegionWithPath {
    /// Creates a new region with path from a raw region with path info
    pub fn from_raw(raw: RegionWithPathInfo) -> Self {
        Self { raw }
    }

    /// Returns the raw version
    pub fn as_raw(&self) -> &RegionWithPathInfo {
        &self.raw
    }

    /// Returns the region object
    #[inline]
    pub fn region(&self) -> &Region {
        Region::ref_cast(&self.raw.prp_prinfo)
    }

    /// Returns the vnode object
    #[inline]
    pub fn vnode(&self) -> &VnodeWithPath {
        VnodeWithPath::ref_cast(&self.raw.prp_vip)
    }
}

impl Debug for RegionWithPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegionWithPath")
            .field("region", &self.region())
            .field("vnode", &self.vnode())
            .finish()
    }
}
