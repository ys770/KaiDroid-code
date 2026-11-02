# Experimental Android 11 system-image build. No boot/vendor image generation.
# Evidence and outstanding boot-chain requirements: docs/N139DL_BUILD_TARGET.md.
TARGET_ARCH := arm
TARGET_ARCH_VARIANT := armv7-a-neon
TARGET_CPU_VARIANT := generic
TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_USES_64_BIT_BINDER := true

# Build the native low-memory allocator; ro.config.low_ram alone does not select it.
# This branch uses single-arena jemalloc without thread caches in svelte mode.
# See docs/N139DL_NATIVE_MEMORY.md for evidence and runtime acceptance criteria.
MALLOC_SVELTE := true

TARGET_NO_BOOTLOADER := true
TARGET_NO_KERNEL := true
TARGET_NO_RECOVERY := true
BOARD_BUILD_SYSTEM_ROOT_IMAGE := true
TARGET_USERIMAGES_USE_EXT4 := true
TARGET_USERIMAGES_USE_F2FS := true
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 834666496
BOARD_EXT4_SHARE_DUP_BLOCKS := true
# Measured build06 staging has 2886 entries; default reserves ~50k inodes.
# Keep growth headroom without spending ~12MiB on unused inode-table entries.
BOARD_SYSTEMIMAGE_EXTFS_INODE_COUNT := 4096
# Existing vendor fstab expects real /cache and /sysdata mount points.
# PRODUCT_BUILD_CACHE_IMAGE remains false: this describes layout, not a new image.
BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_ROOT_EXTRA_FOLDERS := sysdata

# Product/system_ext are directories in the existing static system partition.
TARGET_COPY_OUT_VENDOR := vendor
TARGET_COPY_OUT_PRODUCT := system/product
TARGET_COPY_OUT_SYSTEM_EXT := system/system_ext
BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED := true
# Captured launch API 28 qualifies for AOSP's pre-R sysprop compatibility.
# Retain legacy vendor property access; other neverallow checks remain enabled.
# See docs/N139DL_POLICY_COMPILATION.md, launch-API compatibility probe.
BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW := true
# Android 11 uses this variable for system_ext private policy/context inputs.
BOARD_PLAT_PRIVATE_SEPOLICY_DIR += device/nokia/n139dl/sepolicy/system_ext/private
BOARD_PLAT_PRIVATE_SEPOLICY_DIR += device/nokia/n139dl/sepolicy/integration/private
# Dedicated hinge transport domain; service remains disabled until device validation.
BOARD_PLAT_PRIVATE_SEPOLICY_DIR += device/nokia/n139dl/hall/policy
BOARD_VNDK_VERSION := current
USE_XML_AUDIO_POLICY_CONF := 1

# Build-time test signing only. This key is NOT trusted by the Nokia bootloader.
# Do not flash this image until handset-specific AVB/recovery work is complete.
BOARD_AVB_ENABLE := true
BOARD_AVB_ROLLBACK_INDEX := 0
BOARD_AVB_SYSTEM_KEY_PATH := external/avb/test/data/testkey_rsa2048.pem
BOARD_AVB_SYSTEM_ALGORITHM := SHA256_RSA2048
BOARD_AVB_SYSTEM_ROLLBACK_INDEX := 0
BOARD_AVB_SYSTEM_ROLLBACK_INDEX_LOCATION := 1
