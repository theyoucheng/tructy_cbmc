#
# Copyright (c) 2020, Google, Inc. All rights reserved
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

# Build a userspace app.
#
# This file must be included at the end of userspace app rules.mk files.
#
# args:
# MODULE : module name (required)
# TRUSTY_APP_NAME : Simple name of app (without the path to the source
# 		directory)
# TRUSTY_APP_BUILDDIR : Build directory for trusty apps (app will be built in
# 		$(TRUSTY_APP_BUILDDIR)/$(MODULE))
# MANIFEST : App manifest JSON file
# MODULE_CONSTANTS : JSON files with constants used for both the manifest and C
# 		headers (optional) (CONSTANTS is a deprecated equivalent to
# 		MODULE_CONSTANTS)
#
# The following input arguments control app linking behavior and are not cleared
# after building the app:
# TRUSTY_APP_BASE_LDFLAGS : LDFLAGS for the app
# TRUSTY_APP_ALIGNMENT : Alignment of app image (defaults to 1)
# TRUSTY_APP_MEMBASE : App base address, if fixed
# TRUSTY_APP_SYMTAB_ENABLED : If true do not strip symbols from the
# 		resulting app binary
#
#
# All library.mk input variables are also valid for app, see library.mk for
# additional args and usage.

ifeq ($(strip $(TRUSTY_APP_NAME)),)
TRUSTY_APP_NAME := $(notdir $(MODULE))
endif

TRUSTY_APP := true
BUILDDIR := $(TRUSTY_APP_BUILDDIR)/$(MODULE)

ifneq ($(filter-out bin,$(MODULE_RUST_CRATE_TYPES)),)
$(error $(MODULE) is an app but MODULE_RUST_CRATE_TYPES is not set to "bin")
endif

MODULE_RUST_CRATE_TYPES := bin

include make/library.mk

TRUSTY_APP_LDFLAGS := $(TRUSTY_APP_BASE_LDFLAGS)

ifeq ($(TRUSTY_APP_ALIGNMENT), )
TRUSTY_APP_ALIGNMENT := 1
endif

# If ASLR is disabled, don't make PIEs, it burns space
ifneq ($(ASLR), false)
    # Generate PIE code to allow ASLR to be applied
    ifeq ($(call TOBOOL,$(TRUSTY_USERSPACE)),true)
        TRUSTY_APP_LDFLAGS += -static -pie --no-dynamic-linker -z text -Bsymbolic
    endif
endif

TRUSTY_APP_TOOLCHAIN_PREFIX := $(ARCH_$(ARCH)_TOOLCHAIN_PREFIX)

# TODO: we could find the runtime like this.
# TRUSTY_APP_LIBGCC := $(shell $(CC) $(GLOBAL_COMPILEFLAGS) $(ARCH_$(ARCH)_COMPILEFLAGS) $(THUMBCFLAGS) --rtlib=compiler-rt -print-libgcc-file-name)
# However the compiler currently does not contain non-x86 prebuilts for the
# linux-gnu ABI. We could either get those prebuilts added to the toolchain or
# switch to the android ABI.
# Note there are two copies of compiler-rt in the toolchain - framework and NDK.
# We're using the NDK version because the path is more stable and the difference
# should not matter for this library. (The main difference is which version of
# libcxx they link against, and the builtins do not use C++.)
TRUSTY_APP_LIBGCC := $(CLANG_BINDIR)/../runtimes_ndk_cxx/libclang_rt.builtins-$(STANDARD_ARCH_NAME)-android.a

TRUSTY_APP_LD := $(CLANG_BINDIR)/ld.lld
TRUSTY_APP_OBJCOPY := $(TRUSTY_APP_TOOLCHAIN_PREFIX)objcopy
TRUSTY_APP_OBJDUMP := $(TRUSTY_APP_TOOLCHAIN_PREFIX)objdump
TRUSTY_APP_STRIP := $(TRUSTY_APP_TOOLCHAIN_PREFIX)strip


# App build rules
TRUSTY_APP_BIN := $(BUILDDIR)/$(TRUSTY_APP_NAME).bin
TRUSTY_APP_ELF := $(BUILDDIR)/$(TRUSTY_APP_NAME).elf
TRUSTY_APP_SYMS_ELF := $(BUILDDIR)/$(TRUSTY_APP_NAME).syms.elf
TRUSTY_APP_ALL_OBJS := $(ALLMODULE_OBJS) $(MODULE_EXTRA_OBJECTS)

# Link app elf
ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)
MODULE_RUSTFLAGS += \
	-Z pre-link-args="$(filter-out %.rlib,$(MODULE_EXTRA_OBJECTS))" \
	-C link-args="$(ALLMODULE_OBJS)" \
	-C link-args="$(TRUSTY_APP_LDFLAGS) $(MODULE_LDFLAGS)" \

$(TRUSTY_APP_SYMS_ELF).d:

$(TRUSTY_APP_SYMS_ELF): GLOBAL_RUSTFLAGS := $(GLOBAL_SHARED_RUSTFLAGS) $(GLOBAL_USER_RUSTFLAGS)
$(TRUSTY_APP_SYMS_ELF): ARCH_RUSTFLAGS := $(ARCH_$(ARCH)_RUSTFLAGS)
$(TRUSTY_APP_SYMS_ELF): MODULE_RUSTFLAGS := $(MODULE_RUSTFLAGS) --crate-type=bin
$(TRUSTY_APP_SYMS_ELF): MODULE_RUST_ENV := $(MODULE_RUST_ENV)
$(TRUSTY_APP_SYMS_ELF): $(TRUSTY_APP_RUST_MAIN_SRC) $(TRUSTY_APP_ALL_OBJS) $(TRUSTY_APP_SYMS_ELF).d
	@$(MKDIR)
	@echo compiling $<
	$(NOECHO)$(MODULE_RUST_ENV) $(RUSTC) $(GLOBAL_RUSTFLAGS) $(ARCH_RUSTFLAGS) $(MODULE_RUSTFLAGS) $< --emit "dep-info=$@.d" -o $@

-include $(TRUSTY_APP_SYMS_ELF).d

else

$(TRUSTY_APP_SYMS_ELF): TRUSTY_APP_LD := $(TRUSTY_APP_LD)
$(TRUSTY_APP_SYMS_ELF): TRUSTY_APP_LIBGCC := $(TRUSTY_APP_LIBGCC)
$(TRUSTY_APP_SYMS_ELF): TRUSTY_APP_LDFLAGS := $(TRUSTY_APP_LDFLAGS)
$(TRUSTY_APP_SYMS_ELF): TRUSTY_APP_MEMBASE := $(TRUSTY_APP_MEMBASE)
$(TRUSTY_APP_SYMS_ELF): MODULE_LDFLAGS := $(MODULE_LDFLAGS)
$(TRUSTY_APP_SYMS_ELF): TRUSTY_APP_ALL_OBJS := $(TRUSTY_APP_ALL_OBJS)
$(TRUSTY_APP_SYMS_ELF): $(TRUSTY_APP_ALL_OBJS)
	@$(MKDIR)
	@echo linking $@
	$(TRUSTY_APP_LD) $(TRUSTY_APP_LDFLAGS) $(MODULE_LDFLAGS) $(addprefix -Ttext ,$(TRUSTY_APP_MEMBASE)) --start-group $(TRUSTY_APP_ALL_OBJS) $(TRUSTY_APP_LIBGCC) --end-group -o $@
endif

ifeq ($(call TOBOOL,$(TRUSTY_APP_SYMTAB_ENABLED)),true)
TRUSTY_APP_STRIPFLAGS := --strip-debug
else
TRUSTY_APP_STRIPFLAGS := -s
endif

# And strip it and pad with zeros to be page aligned
$(TRUSTY_APP_ELF): TRUSTY_APP_STRIP := $(TRUSTY_APP_STRIP)
$(TRUSTY_APP_ELF): TRUSTY_APP_ALIGNMENT := $(TRUSTY_APP_ALIGNMENT)
$(TRUSTY_APP_ELF): TRUSTY_APP_STRIPFLAGS := $(TRUSTY_APP_STRIPFLAGS)
$(TRUSTY_APP_ELF): $(TRUSTY_APP_SYMS_ELF)
	@$(MKDIR)
	@echo stripping $<
	$(NOECHO)$(TRUSTY_APP_STRIP) $(TRUSTY_APP_STRIPFLAGS) $< -o $@
	@echo page aligning $<
	$(NOECHO)truncate -s %$(TRUSTY_APP_ALIGNMENT) $@

# build app binary
$(TRUSTY_APP_BIN): TRUSTY_APP_OBJCOPY := $(TRUSTY_APP_OBJCOPY)
$(TRUSTY_APP_BIN): $(TRUSTY_APP_ELF)
	@echo generating image: $@
	$(NOECHO)$(TRUSTY_APP_OBJCOPY) -O binary $< $@

# Also generate listings
all:: $(TRUSTY_APP_BIN) $(TRUSTY_APP_MANIFEST_BIN) $(TRUSTY_APP_ELF)

# Reset local variables
TRUSTY_APP :=
TRUSTY_APP_NAME :=

TRUSTY_APP_BIN :=
TRUSTY_APP_ELF :=
TRUSTY_APP_SYMS_ELF :=
TRUSTY_APP_ALL_OBJS :=
TRUSTY_APP_CONFIGHEADER :=

TRUSTY_APP_TOOLCHAIN_PREFIX :=
TRUSTY_APP_CC :=
TRUSTY_APP_LD :=
TRUSTY_APP_LDFLAGS :=
TRUSTY_APP_OBJCOPY :=
TRUSTY_APP_STRIP :=
TRUSTY_APP_STRIPFLAGS :=
TRUSTY_APP_RUST_MAIN_SRC :=

TRUSTY_APP_APP :=

TRUSTY_APP_MANIFEST_BIN :=
TRUSTY_APP_DISABLE_SCS :=

ALLMODULE_OBJS :=

MODULE_CONSTANTS :=
MODULE_LDFLAGS :=
MODULE_RUSTFLAGS :=
MODULE_RUST_ENV :=

MANIFEST_COMPILER :=
