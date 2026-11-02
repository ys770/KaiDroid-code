# Android 11 bring-up with separately staged TCL framework adaptations.
# Inherit platform packages directly, without emulator hardware or GSI overlays.
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_product.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_product.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/languages_default.mk)

PRODUCT_NAME := kaidroid_n139dl
PRODUCT_DEVICE := n139dl
PRODUCT_BRAND := KaiDroid
PRODUCT_MANUFACTURER := KaiDroid
PRODUCT_MODEL := KaiDroid N139DL development
# Preserve measured original launch API for compatibility/encryption decisions.
PRODUCT_SHIPPING_API_LEVEL := 28
# Captured engineering ro.sf.lcd_density=160; select mdpi resources at link time.
# Keep all locales and fallback resources. See the image-size probe evidence.
PRODUCT_AAPT_PREF_CONFIG := mdpi
DEVICE_PACKAGE_OVERLAYS += device/nokia/n139dl/overlay

# Operator-authorized unattended lab image: root adbd (eng), any USB host.
# Never ship these settings as a consumer release.
ifneq ($(filter eng userdebug,$(TARGET_BUILD_VARIANT)),)
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.adb.secure=0 persist.sys.usb.config=adb
endif

PRODUCT_FULL_TREBLE_OVERRIDE := true
PRODUCT_COMPATIBLE_PROPERTY_OVERRIDE := true
PRODUCT_EXTRA_VNDK_VERSIONS := 29
PRODUCT_USE_DYNAMIC_PARTITIONS := false
PRODUCT_USE_DYNAMIC_PARTITION_SIZE := false
PRODUCT_BUILD_BOOT_IMAGE := false
PRODUCT_BUILD_RECOVERY_IMAGE := false
PRODUCT_BUILD_VENDOR_IMAGE := false
PRODUCT_BUILD_PRODUCT_IMAGE := false
PRODUCT_BUILD_SYSTEM_EXT_IMAGE := false
PRODUCT_BUILD_USERDATA_IMAGE := false
PRODUCT_BUILD_CACHE_IMAGE := false

# Preserve the captured flattened-APEX approach for the first build experiment.
TARGET_FLATTEN_APEX := true
PRODUCT_INSTALL_EXTRA_FLATTENED_APEXES := false

# Supported low-RAM compilation options; device measurements must guide tuning.
# This Android 11 branch emits these through FINAL_DEFAULT_PROPERTIES.
# PRODUCT_SYSTEM_PROPERTIES is not consumed here; missing ro.zygote prevents
# init.${ro.zygote}.rc from importing the framework service.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.config.low_ram=true ro.zygote=zygote32
# Image55: fallback mode0 excluded LTE; mode9 registered on the engineering modem.
# Existing per-subscription settings are preserved; this is the fresh-data default.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.telephony.default_network=9
# Paired with tools/prepare_lmkd_interface_selection.py: stock vendor low-RAM
# post-boot setup disables the legacy kernel killer and expects userspace LMK.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.lmk.use_inkernel_interface=false
# BRT firmware initialization has exceeded the native 2900ms startup deadline.
# Pair with prepare_bluetooth_eng_timeout.py for the outer adapter deadline.
ifeq ($(TARGET_BUILD_VARIANT),eng)
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += bluetooth.enable_timeout_ms=10000
endif
PRODUCT_SYSTEM_SERVER_COMPILER_FILTER := speed-profile
PRODUCT_USE_PROFILE_FOR_BOOT_IMAGE := true
PRODUCT_DEX_PREOPT_BOOT_IMAGE_PROFILE_LOCATION := frameworks/base/config/boot-image-profile.txt
PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false
PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true
TARGET_VNDK_USE_CORE_VARIANT := true

# Installed for inspection; a stock vendor keylayout may take precedence.
PRODUCT_COPY_FILES += \
    device/nokia/n139dl/init/kaidroid-data.rc:system/etc/init/kaidroid-data.rc \
    device/nokia/n139dl/init/kaidroid-diagnostics.rc:system/etc/init/kaidroid-diagnostics.rc \
    device/nokia/n139dl/input/matrix_keypad.kl:system/usr/keylayout/matrix_keypad.kl \
    device/nokia/n139dl/init/zz-kaidroid-surfaceflinger.rc:system/etc/init/zz-kaidroid-surfaceflinger.rc

# Required private bundle from tools/prepare_messaging_network_product.py.
# Preserve the exercised Messaging APK and schema68 provider in fresh builds.
PRODUCT_PACKAGES += KaiDroidTclMessaging KaiDroidTelephonyProvider68

# Private, hash-verified full carrier configuration staged by prepare_private_apns.py.
# Required build input; never silently ship another image without an APN source.
PRODUCT_COPY_FILES += \
    vendor/kaidroid/apns/apns-conf.xml:system/etc/apns-conf.xml

# Private donor module produced by tools/prepare_tcl_launcher.py --rotated-apk.
# The lineage-bearing update and rollback were verified on image15.
KAIDROID_TCL_LAUNCHER ?= true
ifeq ($(KAIDROID_TCL_LAUNCHER),true)
PRODUCT_PACKAGES += KaiDroidTclLauncher
endif

# Private staging from tools/prepare_tcl_ime.py. Enable only for a reviewed
# integration build; preinstalled resource lookup still needs live validation.
KAIDROID_TCL_IME ?= false
ifeq ($(KAIDROID_TCL_IME),true)
PRODUCT_PACKAGES += KaiDroidTclIme
endif

# Requires the paired linkerconfig vendor route for /odm/kaidroid/bin/.
PRODUCT_PACKAGES += kaidroid-memtrack-root-service
PRODUCT_COPY_FILES += \
    device/nokia/n139dl/init/kaidroid-memtrack.rc:system/etc/init/kaidroid-memtrack.rc

PRODUCT_COPY_FILES += \
    device/nokia/n139dl/init/kaidroid-zram.rc:system/etc/init/kaidroid-zram.rc \
    device/nokia/n139dl/fstab.kaidroid-zram:system/etc/fstab.kaidroid-zram

# AOSP Android Go's platform-signed, in-process network stack reduces the
# separate persistent process budget. The module brings its permission config
# and captive-portal companion through required dependencies; validate on-device.
# Keep the Go signing/shared-UID family together: mixing the old tethering or
# cell-broadcast packages with PlatformNetworkPermissionConfig fails scanning.
PRODUCT_PACKAGES += InProcessNetworkStack com.android.tethering.inprocess \
    CellBroadcastAppPlatform CellBroadcastServiceModulePlatform

# Requires tools/prepare_rgb565_render_surface.py applied to frameworks/native.
# Engineering SPI composer expects RGB565 client targets; physically confirmed
# in the bounded runtime trial documented in rgb565-runtime-trial01.json.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.kaidroid.rgb565_client_target=true

# Retain image29+ SPI composition policy in fresh product builds. Requires
# tools/prepare_spi_client_composition.py alongside the RGB565 source patch.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.kaidroid.force_client_composition=true

# Retain image35+ red end-call key policy. Requires the PhoneWindowManager
# adaptation from tools/prepare_power_endcall.py; physical acceptance is pending.
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += ro.kaidroid.power_endcall=true
