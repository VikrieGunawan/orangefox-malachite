
DEVICE_PATH := device/xiaomi/malachite

$(call inherit-product, $(SRC_TARGET_DIR)/product/base.mk)

$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)

$(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota.mk)

$(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/compression_with_xor.mk)

$(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)

$(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/launch_with_vendor_ramdisk.mk)

$(call inherit-product, vendor/twrp/config/common.mk)

PRODUCT_SHIPPING_API_LEVEL := 34
PRODUCT_TARGET_VNDK_VERSION := 36

PRODUCT_PROPERTY_OVERRIDES += persist.sys.fuse.passthrough.enable=true

PRODUCT_PROPERTY_OVERRIDES += ro.twrp.vendor_boot=true

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

PRODUCT_PACKAGES += \
    android.hardware.boot@1.2-mtkimpl \
    android.hardware.boot@1.2-mtkimpl.recovery

PRODUCT_PACKAGES_DEBUG += \
    bootctrl

PRODUCT_USE_DYNAMIC_PARTITIONS := true

PRODUCT_PACKAGES += \
    android.hardware.health@2.1-impl \
    android.hardware.health@2.1-service

PRODUCT_PACKAGES += \
    android.hardware.keymaster@4.1 \
    android.hardware.keymaster@4.0 \
    android.hardware.keymaster@3.0

PRODUCT_PACKAGES += \
    mtk_plpath_utils \
    mtk_plpath_utils.recovery

PRODUCT_EXTRA_RECOVERY_KEYS += \
    $(DEVICE_PATH)/security/miui_releasekey

PRODUCT_SOONG_NAMESPACES += $(DEVICE_PATH)
