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

# Generate Rust bindings for C headers
#
# Bindgen reads C headers and generates compatible Rust declarations of types
# and APIs. This allows us to keep Rust code in sync with C code that it depends
# on.
#
# Input variables:
# MODULE_BINDGEN_ALLOW_VARS
# MODULE_BINDGEN_ALLOW_TYPES
# MODULE_BINDGEN_CTYPES_PREFIX
# MODULE_BINDGEN_FLAGS
# MODULE_BINDGEN_SRC_HEADER

ifeq ($(strip $(MODULE_BINDGEN_SRC_HEADER)),)
$(error $(MODULE): MODULE_BINDGEN_SRC_HEADER is required to use bindgen.mk)
endif

BINDGEN := $(CLANG_TOOLS_BINDIR)/bindgen

MODULE_BINDGEN_OUTPUT_FILE := $(call TOBUILDDIR,$(patsubst %.h,%.rs,$(MODULE_BINDGEN_SRC_HEADER)))

# Trusty rust is all no_std
MODULE_BINDGEN_FLAGS += --use-core --ctypes-prefix 'trusty_sys'

ifneq ($(strip $(MODULE_BINDGEN_CTYPES_PREFIX)),)
MODULE_BINDGEN_FLAGS += --ctypes-prefix $(MODULE_BINDGEN_CTYPES_PREFIX)
endif

MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-var ,$(MODULE_BINDGEN_ALLOW_VARS))
MODULE_BINDGEN_FLAGS += $(addprefix --allowlist-type ,$(MODULE_BINDGEN_ALLOW_TYPES))

BINDGEN_INCLUDES := \
	$(addprefix -I,$(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES)) \
	$(addprefix -I,$(MODULE_INCLUDES)) \

$(MODULE_BINDGEN_OUTPUT_FILE): BINDGEN := $(BINDGEN)
$(MODULE_BINDGEN_OUTPUT_FILE): COMPILE_FLAGS := $(MODULE_COMPILEFLAGS) $(BINDGEN_INCLUDES)
$(MODULE_BINDGEN_OUTPUT_FILE): MODULE_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
$(MODULE_BINDGEN_OUTPUT_FILE): $(MODULE_BINDGEN_SRC_HEADER) $(BINDGEN)
	@$(MKDIR)
	$(BINDGEN) $< -o $@ $(MODULE_BINDGEN_FLAGS) -- $(COMPILE_FLAGS)

MODULE_SRCDEPS += $(MODULE_BINDGEN_OUTPUT_FILE)

MODULE_RUST_ENV += BINDGEN_INC_FILE=$(MODULE_BINDGEN_OUTPUT_FILE)

MODULE_BINDGEN_ALLOW_VARS :=
MODULE_BINDGEN_ALLOW_TYPES :=
MODULE_BINDGEN_CTYPES_PREFIX :=
MODULE_BINDGEN_SRC_HEADER :=

BINDGEN :=
MODULE_BINDGEN_FLAGS :=
BINDGEN_INCLUDES :=
MODULE_BINDGEN_OUTPUT_FILE :=
