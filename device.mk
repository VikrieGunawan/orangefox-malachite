#
# Copyright (C) 2025 The TWRP Open Source Project
# Copyright (C) 2026 OrangeFox Recovery Project
#
# SPDX-License-Identifier: Apache-2.0
#
# Device configuration for Redmi Note 14 Pro 5G / POCO X7 (malachite)
#

DEVICE_PATH := device/xiaomi/malachite

# Configure base.mk
 $(call inherit-product, $(SRC_TARGET_DIR)/product/base.mk)

# Configure core_64_bit_only.mk
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)

# Configure Virtual A/B
 $(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota.mk)

# Configure virtual_ab_ota compression_with_xor.mk
 $(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/compression_with_xor.mk)

# Configure emulated_storage.mk
 $(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)

# Configure launch_with_vendor_ramdisk.mk
 $(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/launch_with_vendor_ramdisk.mk)

# API
PRODUCT_SHIPPING_API_LEVEL := 34
PRODUCT_TARGET_VNDK_VERSION := 36

# Enable Fuse Passthrough
PRODUCT_PROPERTY_OVERRIDES += persist.sys.fuse.passthrough.enable=true

# Recovery in Vendor Boot
PRODUCT_PROPERTY_OVERRIDES += ro.twrp.vendor_boot=true

# A/B
AB_OTA_UPDATER := true
ENABLE_VIRTUAL_AB := true
TARGET_ENFORCE_AB_OTA_PARTITION_LIST := true
AB_OTA_PARTITIONS += \
    apusys \
    audio_dsp \
    boot \
    ccu \
    connsys_gnss \
    countrycode \
    dpm \
    dtbo \
    gpueb \
    gz \
    init_boot \
    lk \
    logo \
    mcf_ota \
    mcupm \
    modem \
    mvpu_algo \
    odm_dlkm \
    pi_img \
    preloader_raw \
    product \
    pvmfw \
    scp \
    spmfw \
    sspm \
    system \
    system_dlkm \
    system_ext \
    tee \
    vbmeta \
    vbmeta_system \
    vbmeta_vendor \
    vcp \
    vendor \
    vendor_boot \
    vendor_dlkm \
    mi_ext

PRODUCT_PACKAGES += \
    update_engine \
    update_engine_sideload \
    update_verifier \
    checkpoint_gc

AB_OTA_POSTINSTALL_CONFIG += \
    RUN_POSTINSTALL_system=true \
    POSTINSTALL_PATH_system=system/bin/mtk_plpath_utils \
    FILESYSTEM_TYPE_system=erofs \
    POSTINSTALL_OPTIONAL_system=true

AB_OTA_POSTINSTALL_CONFIG += \
    RUN_POSTINSTALL_vendor=true \
    POSTINSTALL_PATH_vendor=bin/checkpoint_gc \
    FILESYSTEM_TYPE_vendor=erofs \
    POSTINSTALL_OPTIONAL_vendor=true

# Bootctrl (HIDL boot control untuk MTK UFS)
PRODUCT_PACKAGES += \
    android.hardware.boot@1.2-mtkimpl \
    android.hardware.boot@1.2-mtkimpl.recovery

PRODUCT_PACKAGES_DEBUG += \
    bootctrl

# Dynamic
PRODUCT_USE_DYNAMIC_PARTITIONS := true

# Health
PRODUCT_PACKAGES += \
    android.hardware.health@2.1-impl \
    android.hardware.health@2.1-service

# Keymaster
PRODUCT_PACKAGES += \
    android.hardware.keymaster@4.1 \
    android.hardware.keymaster@4.0 \
    android.hardware.keymaster@3.0

# Mtk plpath utils
PRODUCT_PACKAGES += \
    mtk_plpath_utils \
    mtk_plpath_utils.recovery

# Otacert (MIUI/HyperOS release key untuk sideload OTA resmi)
PRODUCT_EXTRA_RECOVERY_KEYS += \
    $(DEVICE_PATH)/security/miui_releasekey

# Soong namespaces
PRODUCT_SOONG_NAMESPACES += $(DEVICE_PATH)

# ================================================
# TWRP / OrangeFox device configuration
# ================================================

# Theme & UI
TW_THEME := portrait_hdpi
TWRP_NEW_THEME := true
TW_STATUS_ICONS_ALIGN := center
TW_HAS_NO_DISPLAY_CUTOUT := false
TW_FRAMERATE := 120

# Language
TW_DEFAULT_LANGUAGE := id
TW_EXTRA_LANGUAGES := true

# Brightness
TW_BRIGHTNESS_PATH := "/sys/class/leds/lcd-backlight/brightness"
TW_DEFAULT_BRIGHTNESS := 200
TW_MAX_BRIGHTNESS := 2047

# Behavior
TW_NO_LEGACY_PROPS := true
TW_NO_BIND_SYSTEM := true
TW_BACKUP_EXCLUSIONS := /data/fonts
TW_INPUT_BLACKLIST := "hbtp_vm"
TW_USE_NEW_MINADBD := true
TW_EXCLUDE_DEFAULT_USB_INIT := true
TW_EXCLUDE_APEX := true
TW_PREPARE_DATA_MEDIA_EARLY := true
RECOVERY_SDCARD_ON_DATA := true
TW_USE_SERIALNO_PROPERTY_FOR_DEVICE_ID := true

# Version string
TW_DEVICE_VERSION := Redmi_Note_14_Pro_5G
MAINTAINER := namakamu

# Fastbootd
TW_INCLUDE_FASTBOOTD := true

# Tools
TW_INCLUDE_RESETPROP := true
TW_INCLUDE_REPACKTOOLS := true
TW_INCLUDE_LIBRESETPROP := true
TW_INCLUDE_LPDUMP := true
TW_INCLUDE_LPTOOLS := true

# Filesystem features
TW_INCLUDE_NTFS_3G := true
TARGET_USES_MKE2FS := true
TW_INCLUDE_FUSE_NTFS := true
TW_INCLUDE_FUSE_EXFAT := true

# Debug
TARGET_USES_LOGD := true
TWRP_INCLUDE_LOGCAT := true
TWRP_EVENT_LOGGING := true

# Kernel modules dari vendor_boot ramdisk
TW_LOAD_VENDOR_BOOT_MODULES := true
TW_LOAD_VENDOR_MODULES := "haptic.ko"

# AIDL haptics (Xiaomi vibratorfeature)
TW_SUPPORT_INPUT_AIDL_HAPTICS := true
TW_SUPPORT_INPUT_AIDL_HAPTICS_FQNAME := "IVibrator/vibratorfeature"
TW_SUPPORT_INPUT_AIDL_HAPTICS_FIX_OFF := true
# libminuitwrp butuh kedua binding AIDL walau crypto/FBE dimatikan
TW_RECOVERY_ADDITIONAL_RELINK_LIBRARY_FILES += \
    $(TARGET_OUT_SHARED_LIBRARIES)/android.hardware.vibrator-V2-cpp.so \
    $(TARGET_OUT_SHARED_LIBRARIES)/android.hardware.vibrator-V2-ndk.so

# Thermal & battery
TW_CUSTOM_CPU_TEMP_PATH := "/sys/class/thermal/thermal_zone7/temp"
TW_BATTERY_SYSFS_WAIT_SECONDS := 6

# Crypto (FBE decryption HyperOS / Android 15-16)
TW_INCLUDE_CRYPTO := true
TW_INCLUDE_CRYPTO_FBE := true
TW_INCLUDE_FBE_METADATA_DECRYPT := true
TW_USE_FSCRYPT_POLICY := 2
PLATFORM_VERSION := 99.87.36
PLATFORM_VERSION_LAST_STABLE := $(PLATFORM_VERSION)
PLATFORM_SECURITY_PATCH := 2099-12-31
BOOT_SECURITY_PATCH := $(PLATFORM_SECURITY_PATCH)
VENDOR_SECURITY_PATCH := $(PLATFORM_SECURITY_PATCH)
