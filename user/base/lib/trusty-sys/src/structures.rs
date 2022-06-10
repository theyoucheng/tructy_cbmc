use core::ffi::c_void;

// TODO(192472390): We should really be using bindgen to generate these
// interfaces, but we don't have bindgen available for Trusty yet. For now we
// need to be careful to keep these in sync with what the kernel expects in
// syscalls.

#[repr(C)]
pub struct iovec {
    pub iov_base: *const c_void,
    pub iov_len: usize,
}

/**
 * struct dma_pmem - a contiguous physical memory block
 * @paddr: start of physical address
 * @size:  size of this contiguous block
 *
 * Caller passes this struct to prepare_dma syscall, which fills in pinned
 * contiguous physical memory blocks. Caller uses DMA_MULTI_PMEM to tell
 * syscall whether it passes in a single struct or an array.
 */
#[repr(C)]
pub struct dma_pmem {
    pub paddr: u64,
    pub size: u32,
    pub pad: u32,
}

#[repr(C)]
pub struct uuid {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq_and_node: [u8; 8],
}

pub type handle_t = i32;

/*
 *  Is used by wait and wait_any calls to return information
 *  about event.
 */
#[repr(C)]
pub struct uevent {
    pub handle: handle_t,
    pub event: u32,
    pub cookie: *const c_void,
}

impl uevent {
    /// `event` field mask to accept all events
    pub const ALL_EVENTS: u32 = u32::MAX;
}

#[repr(C)]
pub struct ipc_msg {
    pub num_iov: u32,
    pub iov: *const iovec,

    pub num_handles: u32,
    pub handles: *mut handle_t,
}

#[repr(C)]
pub struct ipc_msg_info {
    pub len: usize,
    pub id: u32,
    pub num_handles: u32,
}
