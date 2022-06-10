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

pub use core::fmt::{self, Write};

/// A handle to the standard output stream.
pub struct Stdout(());

/// Creates a new handle for the standard output stream.
pub fn stdout() -> Stdout {
    Stdout(())
}

/// A handle to the standard error stream.
pub struct Stderr(());

/// Creates a new handle for the standard error stream.
pub fn stderr() -> Stderr {
    Stderr(())
}

impl Write for Stdout {
    fn write_str(&mut self, buf: &str) -> fmt::Result {
        _write(trusty_sys::STDOUT_FILENO, buf.as_bytes())
    }
}

impl Write for Stderr {
    fn write_str(&mut self, buf: &str) -> fmt::Result {
        _write(trusty_sys::STDERR_FILENO, buf.as_bytes())
    }
}

pub(crate) fn panic_output() -> Option<impl Write> {
    Some(stderr())
}

fn _write(fd: u32, message: &[u8]) -> fmt::Result {
    let mut iov = trusty_sys::iovec { iov_base: message.as_ptr().cast(), iov_len: message.len() };
    loop {
        // SAFETY: syscall, safe arguments.
        let ret = unsafe { trusty_sys::writev(fd, &iov, 1) };
        if ret < 0 {
            return Err(fmt::Error);
        }
        let ret = ret as usize;
        if ret > iov.iov_len {
            return Err(fmt::Error);
        }
        if ret == iov.iov_len {
            return Ok(());
        }
        // SAFETY: ret has been checked to be less than the length of
        // the buffer
        iov.iov_base = unsafe { iov.iov_base.add(ret) };
        iov.iov_len -= ret;
    }
}
