# Native test target for goauld milestone 1–4.
# Build with NDK:
#   $NDK/ndk-build  (or cmake + android toolchain)
#
# Exports one trivial function and calls strlen in a loop so hooks are observable.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := native_target
LOCAL_SRC_FILES := main.c
LOCAL_LDLIBS := -llog
include $(BUILD_EXECUTABLE)
