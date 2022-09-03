# Copyright (C) 2020 The Android Open Source Project
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

MODULE_INCLUDES += $(LOCAL_DIR)/include

MANIFEST := $(LOCAL_DIR)/manifest.json

CONSTANTS := $(LOCAL_DIR)/include/crasher_consts.json

MODULE_SRCS += \
	$(LOCAL_DIR)/crash-test.c \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/tipc \
	trusty/user/base/lib/unittest \

include make/trusted_app.mk
