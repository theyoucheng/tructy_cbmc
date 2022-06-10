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

use crate::io::panic_output;
use core::fmt::{self, Write};

pub(crate) fn print_internal(args: fmt::Arguments<'_>) {
    if let Some(mut out) = panic_output() {
        let _ = out.write_fmt(args);
    }
}

pub(crate) fn abort_internal() -> ! {
    unsafe { libc::abort() }
}
