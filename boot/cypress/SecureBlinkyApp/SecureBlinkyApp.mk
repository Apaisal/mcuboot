################################################################################
# \file SecureBlinkyApp.mk
# \version 1.0
#
# \brief
# Makefile to describe supported boards and platforms for Cypress MCUBoot based applications.
#
################################################################################
# \copyright
# Copyright 2018-2019 Cypress Semiconductor Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# Cypress' MCUBoot Application supports GCC ARM only at this moment
# Set defaults to:
# 	- compiler GCC
#   - build configuration to Debug
#   - image type to BOOT
COMPILER ?= GCC_ARM
IMG_TYPE ?= BOOT

# image type can be BOOT or UPGRADE
IMG_TYPES = BOOT UPGRADE

# CypressBootloader Image ID to use for signing
CYB_IMG_ID ?= 1

# UPGRADE slots may be located in SMIF area, corresponding policy will be used
SMIF_UPGRADE ?= 0

ifneq ($(COMPILER), GCC_ARM)
$(error Only GCC ARM is supported at this moment)
endif

CUR_APP_PATH = $(CURDIR)/$(APP_NAME)

include $(CUR_APP_PATH)/platforms.mk
include $(CUR_APP_PATH)/libs.mk
include $(CUR_APP_PATH)/toolchains.mk

# Application-specific DEFINES
ifeq ($(IMG_TYPE), BOOT)
	DEFINES_APP := -DBOOT_IMG
else
	DEFINES_APP := -DUPGRADE_IMG
endif

# Define start of application unconditionally,
# as it only can be built for multiimage case now
SECURE_APP_START ?= 0x10000000
SLOT_SIZE ?= 0x10000

# Define RAM regions for targets, since they differ
ifeq ($(PLATFORM), PSOC_064_2M)
DEFINES_APP += -DRAM_START=0x08040000
DEFINES_APP += -DRAM_SIZE=0x20000
ifeq ($(SMIF_UPGRADE), 0)
	# Determine path to multi image policy file
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_multi_CM0_CM4.json
	SLOT_SIZE ?= 0x70000
else ifeq ($(SMIF_UPGRADE), 1)
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_multi_CM0_CM4_smif.json
	SLOT_SIZE ?= 0xC0000
endif
CY_SEC_TOOLS_TARGET := cy8ckit-064b0s2-4343w

else ifeq ($(PLATFORM), PSOC_064_1M)
DEFINES_APP += -DRAM_START=0x08040000
DEFINES_APP += -DRAM_SIZE=0x10000
ifeq ($(SMIF_UPGRADE), 0)
	# Determine path to multi image policy file
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8cproto_064s1_sb/policy/policy_multi_CM0_CM4.json
else ifeq ($(SMIF_UPGRADE), 1)
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8cproto_064s1_sb/policy/policy_multi_CM0_CM4.json
endif
CY_SEC_TOOLS_TARGET := cy8cproto-064b0s1-ble

else ifeq ($(PLATFORM), PSOC_064_512K)
DEFINES_APP += -DRAM_START=0x08010000
DEFINES_APP += -DRAM_SIZE=0x10000
ifeq ($(SMIF_UPGRADE), 0)
	# Determine path to multi image policy file
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_multi_CM0_CM4.json
else ifeq ($(SMIF_UPGRADE), 1)
	IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_multi_CM0_CM4_smif.json
endif
CY_SEC_TOOLS_TARGET := cyb06xx5
endif

DEFINES_APP += -DSECURE_APP_START=$(SECURE_APP_START)
DEFINES_APP += -DSECURE_APP_SIZE=$(SLOT_SIZE)

# Collect Test Application sources
SOURCES_APP_SRC := $(wildcard $(CUR_APP_PATH)/*.c)

# Collect all the sources
SOURCES_APP += $(SOURCES_APP_SRC)
SOURCES_APP += $(SOURCES_PLATFORM)

# Collect includes for BlinkyApp
INCLUDE_DIRS_APP := $(addprefix -I, $(CURDIR))
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH))
INCLUDE_DIRS_APP += $(addprefix -I, $(INCLUDE_DIRS_PLATFORM))

ifeq ($(COMPILER), GCC_ARM)
# TODO: do we need platform-dependent linker?
LINKER_SCRIPT := $(subst /cygdrive/c,c:,$(CUR_APP_PATH)/linker/$(APP_NAME).ld)
else
$(error Only GCC ARM is supported at this moment)
endif

ASM_FILES_APP :=
ASM_FILES_APP += $(ASM_FILES_PLATFORM)

IMGTOOL_PATH ?=	../../scripts/imgtool.py

SIGN_ARGS := sign -H 1024 --pad-header --align 8 -v "2.0" -S $(SLOT_SIZE) -M 512 --overwrite-only -R 0 -k keys/$(SIGN_KEY_FILE).pem

# Output folder
OUT := $(APP_NAME)/out
# Output folder to contain build artifacts
OUT_TARGET := $(OUT)/$(PLATFORM)

OUT_CFG := $(OUT_TARGET)/$(BUILDCFG)

# Set build directory for BOOT and UPGRADE images
ifeq ($(IMG_TYPE), UPGRADE)
	SIGN_ARGS += --pad
	UPGRADE_SUFFIX :=_upgrade
endif

# Output folder
OUT := $(APP_NAME)/out
# Output folder to contain build artifacts
OUT_PLATFORM := $(OUT)/$(PLATFORM)

OUT_CFG := $(OUT_PLATFORM)/$(BUILDCFG)

# Set build directory for BOOT and UPGRADE images
ifeq ($(IMG_TYPE), BOOT)
	OUT_CFG := $(OUT_CFG)/boot
else
	OUT_CFG := $(OUT_CFG)/upgrade
endif

pre_build:
	$(info [PRE_BUILD] - Generating linker script for application $(CUR_APP_PATH)/linker/$(APP_NAME).ld)
	@$(CC) -E -x c $(CFLAGS) $(INCLUDE_DIRS) $(CUR_APP_PATH)/linker/$(APP_NAME)_template.ld | grep -v '^#' >$(CUR_APP_PATH)/linker/$(APP_NAME).ld

# Post build action to execute after main build job
post_build: $(OUT_CFG)/$(APP_NAME).hex
	$(info [POST_BUILD] - Executing post build script for $(APP_NAME))
	$(PYTHON_PATH) -c "from cysecuretools import CySecureTools; tools = CySecureTools('$(CY_SEC_TOOLS_TARGET)', '$(IMAGE_POLICY)'); tools.sign_image('$(OUT_CFG)/$(APP_NAME).hex', $(CYB_IMG_ID))"
