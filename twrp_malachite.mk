# Copyright (C) 2025-2026 OrangeFox Recovery Project
# SPDX-License-Identifier: GPL-3.0-only

$(call inherit-product, $(SRC_TARGET_DIR)/product/languages_full.mk)

$(call inherit-product, device/xiaomi/malachite/device.mk)

$(call inherit-product, vendor/twrp/config/common.mk)

$(call inherit-product, device/xiaomi/malachite/fox_malachite.mk)

PRODUCT_DEVICE := malachite
PRODUCT_BRAND := Redmi
PRODUCT_MODEL := Redmi Note 14 Pro 5G
PRODUCT_MANUFACTURER := Xiaomi
PRODUCT_RELEASE_NAME := Redmi Note 14 Pro 5G
PRODUCT_NAME := twrp_$(PRODUCT_DEVICE)
