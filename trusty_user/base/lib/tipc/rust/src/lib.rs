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

//! # The Trusty IPC Library
//!
//! Implements IPC between Trusty userspace apps, the Trusty kernel, and the
//! non-secure kernel (Android).
//!
//! This library is based around the [`Handle`] type, which is an open
//! communication channel between a client and a service. This handle can send
//! and receive messages which implement [`Serialize`] and [`Deserialize`],
//! respectively. Receiving a message blocks until a message arrives or the
//! handle is closed.

#![no_std]

mod err;
mod handle;
#[allow(non_camel_case_types)]
#[allow(unused)]
mod ipc_sys;
mod serialization;

pub use err::{Result, TipcError};
pub use handle::Handle;
pub use serialization::{Deserialize, Serialize, Serializer};
