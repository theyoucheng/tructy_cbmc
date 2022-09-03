# Copyright (C) 2022 The Android Open Source Project
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

LOG_SRC_DIR = external/rust/crates/log

MODULE_SRCS := $(LOG_SRC_DIR)/src/lib.rs

MODULE_CRATE_NAME := log

MODULE_RUST_EDITION := 2015

MODULE_RUSTFLAGS += \
	--cfg 'atomic_cas' \
	--cfg 'has_atomics' \
	--allow warnings \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/cfg-if-rust \

include make/library.mk
