ifeq ($(call TOBOOL,$(MODULE_ADD_IMPLICIT_DEPS)),true)
ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)
MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libcore-rust \
	trusty/user/base/lib/libcompiler_builtins-rust \

else
MODULE_LIBRARY_DEPS += trusty/user/base/lib/libc-trusty
endif
endif

# Default Rust edition unless otherwise specified
ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),true)
ifeq ($(MODULE_RUST_EDITION),)
MODULE_RUST_EDITION := 2021
endif

MODULE_RUSTFLAGS += --edition $(MODULE_RUST_EDITION)
endif

# Remaining flags only apply to the trusty userspace, not the test-runner, which
# is also built with the library system.
ifeq (true,$(call TOBOOL,$(TRUSTY_USERSPACE)))

# If ASLR is disabled, don't make PIEs, it burns space
ifneq ($(ASLR), false)
    # Generate PIE code to allow ASLR to be applied
    MODULE_COMPILEFLAGS += -fPIC
	MODULE_RUSTFLAGS += -C relocation-model=pic
else
	MODULE_RUSTFLAGS += -C relocation-model=static
endif

# LTO
ifneq (true,$(call TOBOOL,$(MODULE_DISABLE_LTO)))
ifeq (true,$(call TOBOOL,$(USER_LTO_ENABLED)))
MODULE_COMPILEFLAGS += \
	-fvisibility=hidden \
	-flto=thin \

# -fsplit-lto-unit doesn't work with coverage enabled, because we end up
# splitting a module due to coverage instrumentation which hits a bug in LLVM.
ifneq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
MODULE_COMPILEFLAGS += -fsplit-lto-unit
endif

endif

# CFI
MODULE_CFI_ENABLED := false
# TODO(192512327): Re-enable CFI for Rust modules
ifeq ($(call TOBOOL,$(MODULE_IS_RUST)),false)
ifneq (true,$(call TOBOOL,$(MODULE_DISABLE_CFI)))
ifeq (true,$(call TOBOOL,$(CFI_ENABLED)))
MODULE_CFI_ENABLED := true
endif

ifdef USER_CFI_ENABLED
MODULE_CFI_ENABLED := $(call TOBOOL,$(USER_CFI_ENABLED))
endif
endif # !MODULE_DISABLE_CFI
endif

ifeq (true,$(call TOBOOL,$(MODULE_CFI_ENABLED)))
MODULE_COMPILEFLAGS += \
	-fsanitize-blacklist=trusty/kernel/lib/ubsan/exemptlist \
	-fsanitize=cfi \
	-DCFI_ENABLED
MODULE_LIBRARY_DEPS += trusty/kernel/lib/ubsan

ifeq (true,$(call TOBOOL,$(CFI_DIAGNOSTICS)))
MODULE_COMPILEFLAGS += -fno-sanitize-trap=cfi
endif
endif # MODULE_CFI_ENABLED

endif # !MODULE_DISABLE_LTO

# Stack protector
ifneq (true,$(call TOBOOL,$(MODULE_DISABLE_STACK_PROTECTOR)))
ifeq (true,$(call TOBOOL,$(USER_STACK_PROTECTOR)))
MODULE_COMPILEFLAGS += -fstack-protector-strong
endif
else
MODULE_COMPILEFLAGS += -fno-stack-protector
endif

# Shadow call stack
ifeq (true,$(call TOBOOL,$(SCS_ENABLED)))
# set in arch/$(ARCH)/toolchain.mk iff shadow call stack is supported
ifeq (false,$(call TOBOOL,$(ARCH_$(ARCH)_SUPPORTS_SCS)))
$(error Error: Shadow call stack is not supported for $(ARCH))
endif

ifeq (false,$(call TOBOOL,$(TRUSTY_APP_DISABLE_SCS)))
ifeq (false,$(call TOBOOL,$(MODULE_DISABLE_SCS)))
# architectures that support SCS should set the flag that reserves
# a register for the shadow call stack in their toolchain.mk file
MODULE_COMPILEFLAGS += \
	-fsanitize=shadow-call-stack \

ifeq ($(TRUSTY_USER_ARCH),arm64)
# LLVM reserves x18 by default on AArch64 Android, so rust in AOSP doesn't need
# to specify this. We aren't using the Android target so we need to explicitly
# reserve x18 if we want to use SCS.
MODULE_RUSTFLAGS += \
	-C target-feature=+reserve-x18 \

endif

endif
else  # TRUSTY_APP_DISABLE_SCS
$(warning $(MODULE) has set TRUSTY_APP_DISABLE_SCS, this flag only works as intended for apps w/o dependencies)
endif
endif # SCS_ENABLED

# Code coverage
ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
ifeq (false,$(call TOBOOL, $(MODULE_DISABLE_COVERAGE)))
MODULE_LIBRARY_DEPS += trusty/user/base/lib/sancov

# -fno-optimize-sibling-calls is necessary to get correct caller information in
# the sancov instrumentation.
MODULE_COMPILEFLAGS += \
	-fsanitize-coverage-blocklist=trusty/user/base/lib/sancov/exemptlist \
	-fsanitize-coverage=trace-pc-guard \
	-fno-optimize-sibling-calls

endif
endif

# HWASan
ifeq (true,$(call TOBOOL,$(USER_HWASAN_ENABLED)))
MODULE_DEFINES += \
	HWASAN_ENABLED=1 \
	HWASAN_SHADOW_SCALE=4 \

MODULE_LIBRARY_DEPS += trusty/user/base/lib/hwasan
MODULE_COMPILEFLAGS += \
	-fsanitize-blacklist=trusty/user/base/lib/hwasan/exemptlist \
	-fsanitize=hwaddress \
	-mllvm -hwasan-with-tls=0 \
	-mllvm -hwasan-globals=0 \
	-mllvm -hwasan-use-short-granules=0 \

endif

MODULE_DEFINES += TRUSTY_USERSPACE=1

endif # TRUSTY_USERSPACE

MODULE_CFI_ENABLED :=
MODULE_DISABLE_CFI :=
MODULE_DISABLE_COVERAGE :=
MODULE_DISABLE_LTO :=
MODULE_DISABLE_SCS :=
MODULE_DISABLE_STACK_PROTECTOR :=
