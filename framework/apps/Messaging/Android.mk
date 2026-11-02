# Private verified prebuilts staged by prepare_messaging_network_product.py.
# APKs are intentionally absent from Git. Keep their accepted signatures/bytes.
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := KaiDroidTclMessaging
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := APPS
LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)
LOCAL_SRC_FILES := Messaging.apk
LOCAL_CERTIFICATE := PRESIGNED
LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/Messaging.apk
LOCAL_PRIVILEGED_MODULE := true
LOCAL_SYSTEM_EXT_MODULE := true
LOCAL_OVERRIDES_PACKAGES := messaging Mms
LOCAL_OPTIONAL_USES_LIBRARIES := com.qrd.wappush org.apache.http.legacy
LOCAL_REQUIRED_MODULES := kaidroid-tcl-messaging-permissions KaiDroidTelephonyProvider68
LOCAL_DEX_PREOPT := false
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := kaidroid-tcl-messaging-permissions
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := privapp-permissions-kaidroid-messaging.xml
LOCAL_MODULE_STEM := privapp-permissions-kaidroid-messaging.xml
LOCAL_MODULE_PATH := $(TARGET_OUT_SYSTEM_EXT_ETC)/permissions
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := KaiDroidTelephonyProvider68
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := APPS
LOCAL_MODULE_SUFFIX := $(COMMON_ANDROID_PACKAGE_SUFFIX)
LOCAL_SRC_FILES := TelephonyProvider.apk
LOCAL_MODULE_STEM := TelephonyProvider
LOCAL_INSTALLED_MODULE_STEM := TelephonyProvider.apk
LOCAL_MODULE_PATH := $(TARGET_OUT_APPS_PRIVILEGED)
LOCAL_CERTIFICATE := PRESIGNED
LOCAL_REPLACE_PREBUILT_APK_INSTALLED := $(LOCAL_PATH)/TelephonyProvider.apk
LOCAL_PRIVILEGED_MODULE := true
LOCAL_OVERRIDES_PACKAGES := TelephonyProvider
LOCAL_DEX_PREOPT := false
include $(BUILD_PREBUILT)
