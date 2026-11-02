# Root-image placement for a vendor-domain service without changing vendor.img.
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := kaidroid-memtrack-root-service
LOCAL_MODULE_STEM := kaidroid-memtrack-service
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)/odm/kaidroid/bin
LOCAL_SRC_FILES := service.cpp
LOCAL_SHARED_LIBRARIES := libhidlbase libutils android.hardware.memtrack@1.0
LOCAL_CFLAGS := -Wall -Wextra -Werror
include $(BUILD_EXECUTABLE)
