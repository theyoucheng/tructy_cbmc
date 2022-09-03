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

SCUDO_DIR := external/scudo

MODULE_INCLUDES += \
	$(SCUDO_DIR)/standalone \
	$(SCUDO_DIR)/standalone/include \
	$(LOCAL_DIR)/include \

# These C/C++ flags are copied from the Android.bp build rules for Scudo.
MODULE_CFLAGS += \
	-fno-rtti \
	-fno-stack-protector \
	-fno-emulated-tls \
	-Wno-unused-result \
	-DSCUDO_MIN_ALIGNMENT_LOG=4 \

MODULE_CPPFLAGS += \
	-fno-exceptions \
	-nostdinc++ \

MODULE_SRCS += \
	$(SCUDO_DIR)/standalone/checksum.cpp \
	$(SCUDO_DIR)/standalone/common.cpp \
	$(SCUDO_DIR)/standalone/crc32_hw.cpp \
	$(SCUDO_DIR)/standalone/flags.cpp \
	$(SCUDO_DIR)/standalone/flags_parser.cpp \
	$(SCUDO_DIR)/standalone/release.cpp \
	$(SCUDO_DIR)/standalone/report.cpp \
	$(SCUDO_DIR)/standalone/string_utils.cpp \
	$(SCUDO_DIR)/standalone/trusty.cpp \
	$(SCUDO_DIR)/standalone/wrappers_c.cpp \
	$(SCUDO_DIR)/standalone/wrappers_cpp.cpp \

# Scudo relies on libc-trusty's syscall stubs.
MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \

include make/library.mk
