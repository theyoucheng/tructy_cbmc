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

use alloc::collections::TryReserveError;
use core::num::TryFromIntError;
use trusty_std::ffi::TryNewError;
use trusty_sys::c_long;

/// A specialized [`Result`] type for IPC operations.
///
/// This type is used throughout the [`tipc`] crate as a shorthand for result
/// return values. Users outside the current crate should generally use this
/// type as `tipc::Result` rather than shadowing the standard `Result` type.
pub type Result<T> = core::result::Result<T, TipcError>;

/// Errors that an IPC connection may encounter.
#[derive(Clone, Debug)]
pub enum TipcError {
    /// The handle ID returned by the kernel was invalid.
    InvalidHandle,

    /// The provided port was invalid.
    InvalidPort,

    /// Failed to allocate, probably out of memory.
    AllocError,

    /// An integer did not fit into the required size.
    OutOfBounds,

    /// Could not write the entire message. Contains the number of bytes that
    /// were successfully written.
    IncompleteWrite { num_bytes_written: usize },

    /// The provided buffer was not large enough to receive the entire message.
    NotEnoughBuffer,

    /// Some other error occurred.
    UnknownError,

    /// Internal data was not valid
    InvalidData,
}

impl TipcError {
    pub(crate) fn from_uapi(_rc: c_long) -> Self {
        // TODO: convert from C return codes to useful errors
        Self::UnknownError
    }
}

impl From<TryNewError> for TipcError {
    fn from(err: TryNewError) -> Self {
        match err {
            TryNewError::NulError(..) => Self::InvalidPort,
            TryNewError::AllocError => Self::AllocError,
        }
    }
}

impl From<TryReserveError> for TipcError {
    fn from(_err: TryReserveError) -> Self {
        TipcError::AllocError
    }
}

impl From<TryFromIntError> for TipcError {
    fn from(_err: TryFromIntError) -> Self {
        TipcError::OutOfBounds
    }
}
