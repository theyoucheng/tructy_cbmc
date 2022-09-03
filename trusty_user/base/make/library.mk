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

# Build a userspace library for Trusty
#
# args:
# MODULE : module name (required)
# MODULE_SRCS : list of source files, local path (not required for header-only
# 		libraries)
# MODULE_LIBRARY_DEPS : libraries that this module depends on. These libraries
# 		must be built using the new library.mk system (i.e. include
# 		make/library.mk at the end of the library's rules)
# MODULE_DEPS : legacy dependencies that do not use the new library.mk system.
# 		These dependencies will be built exclusively for this module and not
# 		shared with other modules). Do not use this for library dependencies
# 		compatible with library.mk, instead use MODULE_LIBRARY_DEPS.
# MODULE_ADD_IMPLICIT_DEPS : Add basic libraries to MODULE_LIBRARY_DEPS.
# 		Defaults to true. (currently adds libc-trusty)
# MODULE_DEFINES : #defines local to this module
# MODULE_CONSTANTS : JSON files with constants used for both the manifest and C
# 		headers (optional) (CONSTANTS is a deprecated equivalent to
# 		MODULE_CONSTANTS)
# MODULE_COMPILEFLAGS : COMPILEFLAGS local to this module
# MODULE_CFLAGS : CFLAGS local to this module
# MODULE_CPPFLAGS : CPPFLAGS local to this module
# MODULE_ASMFLAGS : ASMFLAGS local to this module
# MODULE_INCLUDES : include directories local to this module
# MODULE_SRCDEPS : extra dependencies that all of this module's files depend on
# MODULE_EXTRA_OBJECTS : extra .o files that should be linked with the module
# MODULE_ARM_OVERRIDE_SRCS : list of source files, local path that should be
# 		force compiled with ARM (if applicable)
# MODULE_RUST_EDITION : Rust edition to compile this crate for (optional)
# MANIFEST : App manifest JSON file, only applicable if this module is an app
#
# Exported flags:
# The following args are the same as their corresponding variables above, but
# will be exported to all users of this library. These flags are also prepended
# to this module's local flags. To override an exported flag, add the
# corresponding override to e.g. MODULE_COMPILEFLAGS.
#
# MODULE_EXPORT_DEFINES
# MODULE_EXPORT_COMPILEFLAGS
# MODULE_EXPORT_CONSTANTS
# MODULE_EXPORT_CFLAGS
# MODULE_EXPORT_CPPFLAGS
# MODULE_EXPORT_ASMFLAGS
# MODULE_EXPORT_INCLUDES

# the minimum library rules.mk file is as follows:
#
# LOCAL_DIR := $(GET_LOCAL_DIR)
# MODULE := $(LOCAL_DIR)
#
# MODULE_SRCS := $(LOCAL_DIR)/source_file.c
#
# include make/library.mk

ifeq ($(call TOBOOL,$(TRUSTY_NEW_MODULE_SYSTEM)),false)

$(info Building kernel library: $(MODULE))

GLOBAL_INCLUDES += $(MODULE_EXPORT_INCLUDES)

# Building for the kernel, turn off independent library build and fall back to
# lk module system.
include make/module.mk

else  # TRUSTY_NEW_MODULE_SYSTEM is true

# Build with the new module system. Currently, the Trusty userspace libraries
# and apps use the new module system, as does the bootloader/test-runner binary.
$(info Building library or app: $(MODULE))

# Reset new module system marker. This will be set again in dependencies by
# userspace_recurse.mk
TRUSTY_NEW_MODULE_SYSTEM :=

ifeq ($(call TOBOOL,$(TRUSTY_APP)),false)
BUILDDIR := $(TRUSTY_LIBRARY_BUILDDIR)
endif

ifneq ($(filter %.rs,$(MODULE_SRCS)$(MODULE_SRCS_FIRST)),)
MODULE_IS_RUST := true
endif

# Add any common flags to the module
include make/common_flags.mk

ifneq ($(INCMODULES),)
$(error $(MODULE) should only be included from other userspace modules that use library.mk. One of the following modules needs to be updated to use the new library system: $(LIB_SAVED_MODULE) $(ALLMODULES))
endif
ifneq ($(GLOBAL_OPTFLAGS),)
$(error $(MODULE) has modified GLOBAL_OPTFLAGS, this variable is deprecated)
endif
ifneq ($(GLOBAL_COMPILEFLAGS),)
$(error $(MODULE) has modified GLOBAL_COMPILEFLAGS, this variable is deprecated, please use MODULE_EXPORT_COMPILEFLAGS)
endif
ifneq ($(GLOBAL_CFLAGS),)
$(error $(MODULE) has modified GLOBAL_CFLAGS, this variable is deprecated, please use MODULE_EXPORT_CFLAGS)
endif
ifneq ($(GLOBAL_CPPFLAGS),)
$(error $(MODULE) has modified GLOBAL_CPPFLAGS, this variable is deprecated, please use MODULE_EXPORT_CPPFLAGS)
endif
ifneq ($(GLOBAL_ASMFLAGS),)
$(error $(MODULE) has modified GLOBAL_ASMFLAGS, this variable is deprecated, please use MODULE_EXPORT_ASMFLAGS)
endif
ifneq ($(GLOBAL_DEFINES),)
$(error $(MODULE) has modified GLOBAL_DEFINES, this variable is deprecated, please use MODULE_EXPORT_DEFINES)
endif
ifneq ($(GLOBAL_INCLUDES),)
$(error $(MODULE) has modified GLOBAL_INCLUDES, this variable is deprecated, please use MODULE_EXPORT_INCLUDES)
endif
ifneq ($(MODULE_OPTFLAGS),)
$(error $(MODULE) sets MODULE_OPTFLAGS, which is deprecated. Please move these flags to another variable.)
endif

ifneq ($(MODULE_EXPORT_RUSTFLAGS),)
$(error $(MODULE) sets MODULE_EXPORT_RUSTFLAGS, which is not supported)
endif

ifneq ($(strip $(MODULE_DEPS)),)
$(warning $(MODULE) is a userspace library module but has deprecated MODULE_DEPS: $(MODULE_DEPS).)
endif

# ALLMODULES is only used for the legacy dependency system, so if a library is
# included in it, something must have gone wrong.
ifneq ($(filter $(MODULE),$(ALLMODULES)),)
ifeq ($(LIB_SAVED_MODULE),)
# We don't know who our parent was because it was a legacy module, so we can't
# give a very good error message here.
$(error Please move $(MODULE) from MODULE_DEPS into MODULE_LIBRARY_DEPS)
else
$(error MODULE $(LIB_SAVED_MODULE) depends on $(MODULE) via MODULE_DEPS, but $(MODULE) is only compatible with MODULE_LIBRARY_DEPS)
endif
endif

ifneq ($(CONSTANTS),)
$(warning $(MODULE) has set CONSTANTS, this variable is deprecated, please use MODULE_CONSTANTS or MODULE_EXPORT_CONSTANTS)
endif
MODULE_CONSTANTS += $(CONSTANTS)

# Register the module in a global registry. This is used to avoid repeatedly
# generating rules for this module from modules that depend on it.
_MODULES_$(MODULE) := T

# Cache exported flags for use in modules that depend on this library.
_MODULES_$(MODULE)_DEFINES := $(MODULE_EXPORT_DEFINES)
_MODULES_$(MODULE)_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS)
_MODULES_$(MODULE)_CONSTANTS := $(MODULE_EXPORT_CONSTANTS)
_MODULES_$(MODULE)_CFLAGS := $(MODULE_EXPORT_CFLAGS)
_MODULES_$(MODULE)_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS)
_MODULES_$(MODULE)_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS)
_MODULES_$(MODULE)_INCLUDES := $(MODULE_EXPORT_INCLUDES)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)
ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)
_MODULES_$(MODULE)_LIBRARIES := $(call TOBUILDDIR,lib$(MODULE_CRATE_NAME)).rlib
_MODULES_$(MODULE)_CRATE_NAME := $(MODULE_CRATE_NAME)
else
_MODULES_$(MODULE)_LIBRARIES := $(call TOBUILDDIR,$(MODULE)).mod.a
endif

DEPENDENCY_MODULE :=

# Recurse into dependencies that this module re-exports flags from. This needs
# to happen before we recurse into regular dependencies in the case of recursive
# dependencies, which need to pick up this module's re-exported flags.
$(foreach dep,$(sort $(MODULE_LIBRARY_EXPORTED_DEPS)),\
	$(eval EXPORT_DEPENDENCY_MODULE := $(dep))\
	$(eval include make/userspace_recurse.mk))

# Re-cache exported flags after adding any flags from exported deps
_MODULES_$(MODULE)_DEFINES := $(MODULE_EXPORT_DEFINES)
_MODULES_$(MODULE)_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS)
_MODULES_$(MODULE)_CFLAGS := $(MODULE_EXPORT_CFLAGS)
_MODULES_$(MODULE)_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS)
_MODULES_$(MODULE)_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS)
_MODULES_$(MODULE)_INCLUDES := $(MODULE_EXPORT_INCLUDES)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)

# We need to avoid duplicate dependencies here, so we use the sort function
# which also de-duplicates.
$(foreach dep,$(sort $(MODULE_LIBRARY_DEPS)),\
	$(eval DEPENDENCY_MODULE := $(dep))\
	$(eval include make/userspace_recurse.mk))

# Include exported flags in the local build
MODULE_LIBRARIES := $(filter-out $(MODULE_LIBRARIES),$(MODULE_EXPORT_LIBRARIES)) $(MODULE_LIBRARIES)
MODULE_EXTRA_OBJECTS := $(filter-out $(MODULE_EXTRA_OBJECTS),$(MODULE_EXPORT_EXTRA_OBJECTS)) $(MODULE_EXTRA_OBJECTS)
MODULE_RLIBS := $(filter-out $(MODULE_RLIBS),$(MODULE_EXPORT_RLIBS)) $(MODULE_RLIBS)
MODULE_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS) $(MODULE_COMPILEFLAGS)
MODULE_CONSTANTS := $(MODULE_EXPORT_CONSTANTS) $(MODULE_CONSTANTS)
MODULE_CFLAGS := $(MODULE_EXPORT_CFLAGS) $(MODULE_CFLAGS)
MODULE_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS) $(MODULE_CPPFLAGS)
MODULE_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS) $(MODULE_ASMFLAGS)
MODULE_LDFLAGS := $(filter-out $(MODULE_LDFLAGS),$(MODULE_EXPORT_LDFLAGS)) $(MODULE_LDFLAGS)
MODULE_INCLUDES := $(MODULE_EXPORT_INCLUDES) $(MODULE_INCLUDES)

# Generate constant headers and manifest, if needed.
include make/gen_manifest.mk

# Generate Rust bindings with bindgen if requested
ifneq ($(strip $(MODULE_BINDGEN_SRC_HEADER)),)
include make/bindgen.mk
endif

ifneq ($(MODULE_SRCS)$(MODULE_SRCS_FIRST),)
# Not a header-only library, so we need to build the source files

ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)

ifneq ($(strip $(MODULE_SRCS_FIRST)),)
$(error $(MODULE) sets MODULE_SRCS_FIRST but is a Rust module, which does not support MODULE_SRCS_FIRST)
endif

ifneq ($(filter-out %.rs,$(MODULE_SRCS)),)
$(error $(MODULE) includes both Rust source files and other source files. Rust modules must only contain Rust sources.)
endif

ifneq ($(words $(filter %.rs,$(MODULE_SRCS))),1)
$(error $(MODULE) includes more than one Rust file in MODULE_SRCS)
endif

ifneq ($(filter-out rlib staticlib bin,$(MODULE_RUST_CRATE_TYPES)),)
$(error $(MODULE) contains unrecognized crate type $(filter-out rlib staticlib bin,$(MODULE_RUST_CRATE_TYPES)) in MODULE_RUST_CRATE_TYPES)
endif

ifeq ($(MODULE_CRATE_NAME),)
$(error $(MODULE) is a Rust module but does not set MODULE_CRATE_NAME)
endif

MODULE_RUSTFLAGS += --crate-name=$(MODULE_CRATE_NAME)

ifeq ($(strip $(MODULE_RUST_CRATE_TYPES)),)
MODULE_RUST_CRATE_TYPES := rlib
endif

MODULE_RUSTFLAGS += $(addprefix --extern ,$(MODULE_RLIBS))

MODULE_RUSTFLAGS += --emit link

MODULE_RSOBJS :=

ifneq ($(filter rlib,$(MODULE_RUST_CRATE_TYPES)),)
MODULE_CRATE_OUTPUT := $(call TOBUILDDIR,lib$(MODULE_CRATE_NAME).rlib)
MODULE_RSOBJS += $(MODULE_CRATE_OUTPUT)
$(MODULE_CRATE_OUTPUT): MODULE_RUSTFLAGS := $(MODULE_RUSTFLAGS) --crate-type=rlib
MODULE_EXPORT_RLIBS += $(MODULE_CRATE_NAME)=$(MODULE_CRATE_OUTPUT)
endif

ifneq ($(filter staticlib,$(MODULE_RUST_CRATE_TYPES)),)
MODULE_CRATE_OUTPUT := $(call TOBUILDDIR,lib$(MODULE_CRATE_NAME).a)
MODULE_RSOBJS += $(MODULE_CRATE_OUTPUT)
$(MODULE_CRATE_OUTPUT): MODULE_RUSTFLAGS := $(MODULE_RUSTFLAGS) --crate-type=staticlib
endif

ifneq ($(filter bin,$(MODULE_RUST_CRATE_TYPES)),)
# Used in trusted_app.mk
TRUSTY_APP_RUST_MAIN_SRC := $(filter %.rs,$(MODULE_SRCS))
endif

MODULE_CRATE_OUTPUT :=

_MODULES_$(MODULE)_CRATE_INDEX := $(GLOBAL_CRATE_COUNT)
GLOBAL_CRATE_COUNT := $(shell echo $$(($(GLOBAL_CRATE_COUNT)+1)))

define CRATE_CONFIG :=
{
	"display_name": "$(MODULE_CRATE_NAME)",
	"root_module": "$(filter %.rs,$(MODULE_SRCS))",
	"edition": "$(MODULE_RUST_EDITION)",
	"deps": [
		$(call STRIP_TRAILING_COMMA,$(foreach dep,$(sort $(MODULE_LIBRARY_DEPS)),\
				$(if $(_MODULES_$(dep)_CRATE_NAME),{"name": "$(_MODULES_$(dep)_CRATE_NAME)"$(COMMA) "crate": $(_MODULES_$(dep)_CRATE_INDEX)}$(COMMA))))
	]
},

endef
RUST_ANALYZER_CRATES := $(RUST_ANALYZER_CRATES)$(CRATE_CONFIG)
CRATE_CONFIG :=

endif

# Save our current module because module.mk clears it.
LIB_SAVED_MODULE := $(MODULE)
LIB_SAVED_MODULE_LIBRARY_DEPS := $(MODULE_LIBRARY_DEPS)

# Save the rust flags for use in trusted_app.mk. userspace_recurse.mk will clean
# up after us.
LIB_SAVED_MODULE_RUSTFLAGS := $(MODULE_RUSTFLAGS)

ALLMODULE_OBJS :=
MODULE_LIBRARY_DEPS :=

$(MODULE_RSOBJS): ARCH_RUSTFLAGS := $(ARCH_$(ARCH)_RUSTFLAGS)
$(MODULE_RSOBJS): GLOBAL_RUSTFLAGS := $(GLOBAL_SHARED_RUSTFLAGS) $(GLOBAL_USER_RUSTFLAGS)
$(MODULE_RSOBJS): MODULE_RUST_ENV := $(MODULE_RUST_ENV)

include make/module.mk

# Handle any MODULE_DEPS
include make/recurse.mk

MODULE_LIBRARY_DEPS := $(LIB_SAVED_MODULE_LIBRARY_DEPS)
MODULE := $(LIB_SAVED_MODULE)
MODULE_RUSTFLAGS := $(LIB_SAVED_MODULE_RUSTFLAGS)

$(BUILDDIR)/%: CC := $(CCACHE) $(CLANG_BINDIR)/clang
$(BUILDDIR)/%: RUSTC := $(RUST_BINDIR)/rustc
$(BUILDDIR)/%.o: GLOBAL_OPTFLAGS := $(GLOBAL_SHARED_OPTFLAGS) $(GLOBAL_USER_OPTFLAGS) $(ARCH_OPTFLAGS)
$(BUILDDIR)/%.o: GLOBAL_COMPILEFLAGS := $(GLOBAL_SHARED_COMPILEFLAGS) $(GLOBAL_USER_COMPILEFLAGS)
$(BUILDDIR)/%.o: GLOBAL_CFLAGS   := $(GLOBAL_SHARED_CFLAGS) $(GLOBAL_USER_CFLAGS)
$(BUILDDIR)/%.o: GLOBAL_CPPFLAGS := $(GLOBAL_SHARED_CPPFLAGS) $(GLOBAL_USER_CPPFLAGS)
$(BUILDDIR)/%.o: GLOBAL_ASMFLAGS := $(GLOBAL_SHARED_ASMFLAGS) $(GLOBAL_USER_ASMFLAGS)
$(BUILDDIR)/%.o: GLOBAL_INCLUDES := $(addprefix -I,$(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES))
$(BUILDDIR)/%.o: ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
$(BUILDDIR)/%.o: ARCH_CFLAGS := $(ARCH_$(ARCH)_CFLAGS)
$(BUILDDIR)/%.o: THUMBCFLAGS := $(ARCH_$(ARCH)_THUMBCFLAGS)
$(BUILDDIR)/%.o: ARCH_CPPFLAGS := $(ARCH_$(ARCH)_CPPFLAGS)
$(BUILDDIR)/%.o: ARCH_ASMFLAGS := $(ARCH_$(ARCH)_ASMFLAGS)

ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)
LIBRARY_ARCHIVE := $(filter %.rlib,$(ALLMODULE_OBJS))
else
LIBRARY_ARCHIVE := $(filter %.mod.a,$(ALLMODULE_OBJS))
endif

MODULE_EXPORT_LIBRARIES += $(LIBRARY_ARCHIVE)
MODULE_EXPORT_EXTRA_OBJECTS += $(filter-out $(LIBRARY_ARCHIVE),$(ALLMODULE_OBJS))

# Append dependency libraries into ALLMODULE_OBJS.
ALLMODULE_OBJS := $(ALLMODULE_OBJS) $(filter-out $(ALLMODULE_OBJS),$(MODULE_LIBRARIES))

endif # MODULE is not a header-only library

_MODULES_$(MODULE)_LIBRARIES := $(MODULE_EXPORT_LIBRARIES)
_MODULES_$(MODULE)_EXTRA_OBJECTS := $(MODULE_EXPORT_EXTRA_OBJECTS)
_MODULES_$(MODULE)_RLIBS := $(MODULE_EXPORT_RLIBS)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)

endif # building userspace module

# Reset all variables for the next module
MODULE :=
MODULE_CRATE_NAME :=
MODULE_LIBRARY_DEPS :=
MODULE_LIBRARY_EXPORTED_DEPS :=
MODULE_LIBRARIES :=
MODULE_RLIBS :=
MODULE_RSOBJS :=
LIB_SAVED_MODULE :=
LIB_SAVED_ALLMODULE_OBJS :=
MODULE_RUST_CRATE_TYPES :=

MODULE_EXPORT_LIBRARIES :=
MODULE_EXPORT_RLIBS :=
MODULE_EXPORT_EXTRA_OBJECTS :=
MODULE_EXPORT_DEFINES :=
MODULE_EXPORT_COMPILEFLAGS :=
MODULE_EXPORT_CONSTANTS :=
MODULE_EXPORT_CFLAGS :=
MODULE_EXPORT_CPPFLAGS :=
MODULE_EXPORT_ASMFLAGS :=
MODULE_EXPORT_INCLUDES :=
MODULE_EXPORT_LDFLAGS :=
