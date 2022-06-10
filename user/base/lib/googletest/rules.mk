LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GTEST_DIR := external/googletest/googletest

# Export gtest headers.
MODULE_EXPORT_INCLUDES += $(GTEST_DIR)/include

# gtest has internal includes relative to its root directory.
MODULE_INCLUDES += $(GTEST_DIR)

# Disable optional features.
MODULE_COMPILEFLAGS += \
	-DGTEST_HAS_CLONE=0 \
	-DGTEST_HAS_EXCEPTIONS=0 \
	-DGTEST_HAS_POSIX_RE=0 \
	-DGTEST_HAS_PTHREAD=0 \
	-DGTEST_HAS_RTTI=0 \
	-DGTEST_HAS_STD_WSTRING=0 \
	-DGTEST_HAS_SEH=0 \
	-DGTEST_HAS_STREAM_REDIRECTION=0 \
	-DGTEST_LINKED_AS_SHARED_LIBRARY=0 \
	-DGTEST_CREATE_SHARED_LIBRARY=0 \
	-DGTEST_HAS_DEATH_TEST=0 \

# Horrible hack for preventing OS detection.
# If we don't prevent OS detection, gtest-port.h will try to enable death tests.
MODULE_COMPILEFLAGS += -DGTEST_INCLUDE_GTEST_INTERNAL_GTEST_PORT_ARCH_H_=1

# After disabling a bunch of features, there are dead constants.
MODULE_COMPILEFLAGS += -Wno-unused-const-variable

# Explicitly list the files instead of using gtest-all.cc so the build can be
# parallelized. Note we need to build all the files because of how command line
# flags are handled. For example, we don't support death tests, but still need
# to compile gtest-death-test.cc because gtest.cc references
# GTEST_FLAG(death_test_style).
MODULE_SRCS := \
	$(GTEST_DIR)/src/gtest.cc \
	$(GTEST_DIR)/src/gtest-death-test.cc \
	$(GTEST_DIR)/src/gtest-filepath.cc \
	$(GTEST_DIR)/src/gtest-matchers.cc \
	$(GTEST_DIR)/src/gtest-port.cc \
	$(GTEST_DIR)/src/gtest-printers.cc \
	$(GTEST_DIR)/src/gtest-test-part.cc \
	$(GTEST_DIR)/src/gtest-typed-test.cc \

MODULE_LIBRARY_DEPS += \
        trusty/user/base/lib/libstdc++-trusty \

include make/library.mk
