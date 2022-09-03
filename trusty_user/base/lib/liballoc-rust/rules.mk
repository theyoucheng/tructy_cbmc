# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

LIBALLOC_DIR = $(RUST_BINDIR)/../src/stdlibs/library/alloc

MODULE_SRCS := $(LIBALLOC_DIR)/src/lib.rs

MODULE_CRATE_NAME := alloc

MODULE_RUST_EDITION := 2018

# TODO(196094086): enable when https://github.com/rust-lang/rust/pull/86938 or a
# replacement lands in the toolchain.
#
#	--cfg 'no_global_oom_handling' \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libcompiler_builtins-rust \
	trusty/user/base/lib/libcore-rust \

include make/library.mk
