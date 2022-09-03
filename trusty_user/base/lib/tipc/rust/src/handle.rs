/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::ipc_sys::{handle_t, INFINITE_TIME, IPC_CONNECT_WAIT_FOR_PORT};
use crate::serialization::Serializer;
use crate::{Deserialize, Serialize, TipcError};
use core::convert::TryInto;
use core::mem::MaybeUninit;
use trusty_std::alloc::{FallibleVec, Vec};
use trusty_std::ffi::CStr;

/// An open IPC connection.
///
/// This handle knows how to send and receive messages which implement
/// [`Serialize`] and [`Deserialize`] respectively. Serialization and parsing
/// are handled by the message itself.
///
/// The handle owns its connection, which is closed when this struct is dropped.
/// Do not rely on the connection being closed for protocol correctness, as the
/// drop method may not always be called.
#[repr(transparent)]
pub struct Handle(handle_t);

/// Maximum number of handles that can be transferred in an IPC message at once.
const MAX_MSG_HANDLES: usize = 8;

impl Handle {
    /// Open a client connection to the given service.
    ///
    /// The service `port` can be either a Trusty TA or kernel port name. This
    /// call is synchronous and will block until the specified port exists.
    ///
    /// # Examples
    ///
    /// Open a TIPC connection to `com.android.trusty.test_port`:
    ///
    /// ```
    /// use tipc::Handle;
    /// use trusty_std::ffi::CStr;
    ///
    /// let port = CStr::from_bytes_with_nul(b"com.android.trusty.test_port\0")
    ///                  .unwrap();
    ///
    /// if let Ok(handle) = Handle::connect(port) {
    ///     println!("Connection successful");
    /// } else {
    ///     println!("Connection attempt failed");
    /// }
    /// ```
    pub fn connect(port: &CStr) -> crate::Result<Self> {
        // SAFETY: external syscall. port is guaranteed to be a well-formed,
        // null-terminated C string.
        let rc = unsafe { trusty_sys::connect(port.as_ptr(), IPC_CONNECT_WAIT_FOR_PORT as u32) };
        if rc < 0 {
            Err(TipcError::from_uapi(rc))
        } else {
            rc.try_into().map(Handle).or(Err(TipcError::InvalidHandle))
        }
    }

    /// Send an IPC message.
    ///
    /// Serializes `msg` using its [`Serialize`] implementation and send it
    /// across this IPC connection. Attempts to serialize the message in-place
    /// without new allocations.
    pub fn send<'s, T: Serialize<'s>>(&self, msg: &'s T) -> crate::Result<()> {
        let mut serializer = BorrowingSerializer::default();
        msg.serialize(&mut serializer)?;
        self.send_vectored(&serializer.buffers[..], &serializer.handles[..])
    }

    /// Receive an IPC message.
    ///
    /// Receives a message into the given temporary `buffer`, and deserializes
    /// the received message into a `T` using `T::Deserialize`. If the received
    /// message does not fit into `buffer` this method will return error value
    /// [`TipcError::NotEnoughBuffer`]. In the case of insufficient buffer
    /// space, the message data will be lost and must be resent to recover.
    ///
    /// TODO: Support a timeout for the wait.
    pub fn recv<T: Deserialize>(&self, buffer: &mut [u8]) -> Result<T, T::Error> {
        let _ = self.wait(None)?;
        let mut handles: [Handle; MAX_MSG_HANDLES] = Default::default();
        let (byte_count, handle_count) = self.recv_vectored(&[buffer], &mut handles)?;
        T::deserialize(&buffer[..byte_count], &handles[..handle_count])
    }

    /// Receive raw bytes and handles into slices of buffers and handles.
    ///
    /// Returns a tuple of the number of bytes written into the buffer and the
    /// number of handles received. `handles` should have space for at least
    /// [`MAX_MSG_HANDLES`].
    fn recv_vectored(
        &self,
        buffers: &[&mut [u8]],
        handles: &mut [Handle],
    ) -> crate::Result<(usize, usize)> {
        self.get_msg(|msg_info| {
            if msg_info.len > buffers.iter().map(|b| b.len()).sum() {
                return Err(TipcError::NotEnoughBuffer);
            }

            let mut iovs = Vec::new();
            iovs.try_reserve_exact(buffers.len())?;
            iovs.extend(buffers.iter().map(|buf| trusty_sys::iovec {
                iov_base: buf.as_ptr().cast(),
                iov_len: buf.len(),
            }));

            let mut msg = trusty_sys::ipc_msg {
                num_iov: iovs.len().try_into()?,
                iov: iovs.as_ptr(),

                num_handles: handles.len().try_into()?,
                handles: handles.as_ptr() as *mut i32,
            };

            // SAFETY: syscall, pointer is initialized with valid data and
            // mutably borrowed. The buffers that the msg refers to are valid
            // and writable across this call. `Handle` is a transparent wrapper
            // around `handle_t`, i.e. `i32` so we can safely cast the handles
            // slice to an `i32` pointer. Although the syscall requires a
            // mutable handle pointer, it does not mutate these handles, so we
            // can safely cast the immutable slice to mutable pointer.
            let rc = unsafe { trusty_sys::read_msg(self.as_raw_fd(), msg_info.id, 0, &mut msg) };

            if rc < 0 {
                Err(TipcError::from_uapi(rc))
            } else {
                Ok((rc.try_into()?, msg.num_handles.try_into()?))
            }
        })
    }

    /// Send a set of buffers and file/memref handles.
    ///
    /// Sends a set of buffers and set of handles at once. `buf` must fit in the
    /// message queue and `handles` must contain no more than
    /// [`MAX_MSG_HANDLES`].
    fn send_vectored(&self, buffers: &[&[u8]], handles: &[Handle]) -> crate::Result<()> {
        let mut iovs = Vec::new();
        iovs.try_reserve_exact(buffers.len())?;
        iovs.extend(
            buffers
                .iter()
                .map(|buf| trusty_sys::iovec { iov_base: buf.as_ptr().cast(), iov_len: buf.len() }),
        );
        let total_num_bytes = buffers.iter().map(|b| b.len()).sum();

        let mut msg = trusty_sys::ipc_msg {
            num_iov: iovs.len().try_into()?,
            iov: iovs.as_ptr(),

            num_handles: handles.len().try_into()?,
            handles: handles.as_ptr() as *mut i32,
        };
        // SAFETY: syscall, pointer is initialized with valid data and mutably
        // borrowed. The buffers that the msg refers to are valid and writable
        // across this call. `Handle` is a transparent wrapper around
        // `handle_t`, i.e. `i32` so we can safely cast the handles slice to an
        // `i32` pointer. Although the syscall requires a mutable handle
        // pointer, it does not mutate these handles, so we can safely cast the
        // immutable slice to mutable pointer.
        let rc = unsafe { trusty_sys::send_msg(self.as_raw_fd(), &mut msg) };
        if rc < 0 {
            Err(TipcError::from_uapi(rc))
        } else if rc as usize != total_num_bytes {
            Err(TipcError::IncompleteWrite { num_bytes_written: rc as usize })
        } else {
            Ok(())
        }
    }

    /// Get the raw file descriptor of this handle.
    fn as_raw_fd(&self) -> i32 {
        self.0
    }

    /// Wait for an event on this handle for `timeout` milliseconds, or
    /// indefinitely if `None`.
    pub(crate) fn wait(&self, timeout: Option<u32>) -> crate::Result<trusty_sys::uevent> {
        let timeout = timeout.unwrap_or(INFINITE_TIME);
        let mut uevent = MaybeUninit::zeroed();
        // SAFETY: syscall, uevent is borrowed mutably and outlives the call
        let rc = unsafe { trusty_sys::wait(self.as_raw_fd(), uevent.as_mut_ptr(), timeout) };
        if rc != 0 {
            Err(TipcError::from_uapi(rc))
        } else {
            // SAFETY: If the wait call succeeded, the uevent structure has been
            // fully initialized.
            let uevent = unsafe { uevent.assume_init() };
            Ok(uevent)
        }
    }

    /// Receive an IPC message.
    ///
    /// The `func` callback must call `trusty_sys::read_msg()` with the provided
    /// message id from `ipc_msg_info` to read the message bytes. A message is
    /// only valid for the lifetime of this callback and the message bytes
    /// should be copied into the return value, if needed.
    fn get_msg<F, R>(&self, func: F) -> crate::Result<R>
    where
        F: Fn(&trusty_sys::ipc_msg_info) -> crate::Result<R>,
    {
        let mut msg_info: MaybeUninit<trusty_sys::ipc_msg_info> = MaybeUninit::uninit();

        // SAFETY: syscall, msg_info pointer is mutably borrowed and will be
        // correctly initialized if the syscall returns 0.
        let msg_info = unsafe {
            let rc = trusty_sys::get_msg(self.as_raw_fd(), msg_info.as_mut_ptr());
            if rc != 0 {
                return Err(TipcError::from_uapi(rc));
            }
            msg_info.assume_init()
        };

        let ret = func(&msg_info);

        // SAFETY: syscall with safe arguments
        let put_msg_rc = unsafe { trusty_sys::put_msg(self.as_raw_fd(), msg_info.id) };

        // prefer returning the callback error to the put_msg error, if any
        if put_msg_rc != 0 {
            Err(ret.err().unwrap_or_else(|| TipcError::from_uapi(put_msg_rc)))
        } else {
            ret
        }
    }
}

impl Default for Handle {
    fn default() -> Self {
        Self(-1)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY syscall with safe arguments
        unsafe {
            let _ = trusty_sys::close(self.as_raw_fd());
        }
    }
}

/// A serializer that borrows its input bytes and does not allocate.
#[derive(Default)]
struct BorrowingSerializer<'a> {
    buffers: Vec<&'a [u8]>,
    handles: Vec<Handle>,
}

impl<'a> Serializer<'a> for BorrowingSerializer<'a> {
    type Ok = ();
    type Error = TipcError;

    fn serialize_bytes(&mut self, bytes: &'a [u8]) -> Result<Self::Ok, Self::Error> {
        self.buffers.try_push(bytes).or(Err(TipcError::AllocError))
    }

    fn serialize_handle(&mut self, handle: &'a Handle) -> Result<Self::Ok, Self::Error> {
        self.handles.try_push(Handle(handle.as_raw_fd())).or(Err(TipcError::AllocError))
    }
}
