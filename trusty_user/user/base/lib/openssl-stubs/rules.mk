LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)
MODULE_USER := true

MODULE_SRCS := \
	$(LOCAL_DIR)/bio.c \
	$(LOCAL_DIR)/rand.c \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/rng \
	external/boringssl \

include make/library.mk
