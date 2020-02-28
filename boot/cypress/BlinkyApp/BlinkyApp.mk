################################################################################
# \file targets.mk
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

# BlinkyApp will be be run by CyBootloader wih multi image support
MULTI_IMAGE ?= 1

# UPGRADE slots may be located in SMIF area, corresponding policy will be used
SMIF_UPGRADE ?= 0

# CypressBootloader Image ID to use for signing, defualt is ID for multi image
CYB_IMG_ID ?= 16

# Default secure counter value
SEC_CNT ?= 0

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

# Define start of application as it can be built for Secure Boot target
# Also check if this image will be used with multi image CyBootloader
#ifneq ($(filter $(PLATFORM), $(SB_PLATFORMS)),)
#2M devices case
ifeq ($(PLATFORM), PSOC_064_2M)
	# Set RAM start and size
	DEFINES_APP += -DRAM_START=0x08008000
	DEFINES_APP += -DRAM_SIZE=0x3000
	CY_SEC_TOOLS_TARGET := cy8ckit-064b0s2-4343w
	# Set flash start and size
	ifeq ($(MULTI_IMAGE), 0)
		CYB_IMG_ID := 4
		DEFINES_APP += -DUSER_APP_START=0x10000000
		ifeq ($(SMIF_UPGRADE), 0)
			SINGLE_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_single_stage_CM4.json
			DEFINES_APP += -DUSER_APP_SIZE=0xE1000
			SLOT_SIZE ?= 0xE1000
		else ifeq ($(SMIF_UPGRADE), 1)
			SINGLE_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_single_stage_CM4_smif.json
			DEFINES_APP += -DUSER_APP_SIZE=0x180000
			SLOT_SIZE ?= 0x180000
		endif
	else
		ifeq ($(SMIF_UPGRADE), 0)
			# Determine path to multi image policy file
			MULTI_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_multi_CM0_CM4.json
			DEFINES_APP += -DUSER_APP_START=0x100E0000
			DEFINES_APP += -DUSER_APP_SIZE=0x70000
			SLOT_SIZE ?= 0x70000
		else ifeq ($(SMIF_UPGRADE), 1)
			MULTI_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8ckit_064x0s2_4343w/policy/policy_multi_CM0_CM4_smif.json
			DEFINES_APP += -DUSER_APP_START=0x100C0000
			DEFINES_APP += -DUSER_APP_SIZE=0xC0000
			SLOT_SIZE ?= 0xC0000
		endif
	endif
endif

ifeq ($(PLATFORM), PSOC_064_1M)
	# Set RAM start and size
	DEFINES_APP += -DRAM_START=0x08010000
	DEFINES_APP += -DRAM_SIZE=0x5000
	CY_SEC_TOOLS_TARGET := cy8cproto-064b0s1-ble
	# Set flash start and size
	ifeq ($(MULTI_IMAGE), 0)
		CYB_IMG_ID := 4
		SINGLE_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8cproto_064s1_sb/policy/policy_single_stage_CM4.json
		DEFINES_APP += -DUSER_APP_START=0x10000000
        SLOT_SIZE ?= 0x10000
	else
		# Determine path to multi image policy file
		MULTI_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cy8cproto_064s1_sb/policy/policy_multi_CM0_CM4.json
		DEFINES_APP += -DUSER_APP_START=0x10020000
        SLOT_SIZE ?= 0x10000
	endif
endif

ifeq ($(PLATFORM), PSOC_064_512K)
	# Set RAM start and size
	DEFINES_APP += -DRAM_START=0x08020000
	DEFINES_APP += -DRAM_SIZE=0x5000
	CY_SEC_TOOLS_TARGET := cyb06445lqi-s3d42
	# Set flash start and size
	ifeq ($(MULTI_IMAGE), 0)
		CYB_IMG_ID := 4
		DEFINES_APP += -DUSER_APP_START=0x10000000
		ifeq ($(SMIF_UPGRADE), 0)
			SINGLE_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_single_stage_CM4.json
			DEFINES_APP += -DUSER_APP_SIZE=0x20000
			SLOT_SIZE ?= 0x20000
		else ifeq ($(SMIF_UPGRADE), 1)
			SINGLE_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_single_stage_CM4_smif.json
			DEFINES_APP += -DUSER_APP_SIZE=0x20000
			SLOT_SIZE ?= 0x20000
		endif
	else
		ifeq ($(SMIF_UPGRADE), 0)
			# Determine path to multi image policy file
			MULTI_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_multi_CM0_CM4.json
		else ifeq ($(SMIF_UPGRADE), 1)
			MULTI_IMAGE_POLICY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/cyb06xx5/policy/policy_multi_CM0_CM4_smif.json
		endif
		DEFINES_APP += -DUSER_APP_START=0x10040000
		SLOT_SIZE ?= 0x10000
	endif
endif

ifeq ($(PLATFORM), PSOC_062_2M)
	DEFINES_APP += -DRAM_START=0x08000000
	DEFINES_APP += -DRAM_SIZE=0x20000
	DEFINES_APP += -DUSER_APP_START=0x10018000
    SLOT_SIZE ?= 0x10000
endif

# Collect Test Application sources
SOURCES_APP_SRC := $(wildcard $(CUR_APP_PATH)/*.c)
# Collect all the sources
SOURCES_APP += $(SOURCES_APP_SRC)

# Collect includes for BlinkyApp
INCLUDE_DIRS_APP := $(addprefix -I, $(CURDIR))
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH))

# Overwite path to linker script if custom is required, otherwise default from BSP is used
ifeq ($(COMPILER), GCC_ARM)
LINKER_SCRIPT := $(subst /cygdrive/c,c:,$(CUR_APP_PATH)/linker/$(APP_NAME).ld)
else
$(error Only GCC ARM is supported at this moment)
endif

ASM_FILES_APP :=

# We still need this for MCUBoot apps signing
IMGTOOL_PATH ?=	../../scripts/imgtool.py

SIGN_ARGS := sign --header-size 1024 --pad-header --align 8 -v "2.0" -S $(SLOT_SIZE) -M 512 --overwrite-only -k keys/$(SIGN_KEY_FILE).pem
ifeq ($(SMIF_UPGRADE), 0)
	SIGN_ARGS += -R 0
else
	SIGN_ARGS += -R 0xFF
endif

# Add a TFM secure counter to the protected image area
SIGN_ARGS += -s $(SEC_CNT)
# Add a Cypress custom TLV tags to the protected image area
IMG_CONTEXT := --imageid 'B' $(CYB_IMG_ID) --rollbackcounter 'B' $(SEC_CNT)

# Output folder
OUT := $(APP_NAME)/out
# Output folder to contain build artifacts
OUT_TARGET := $(OUT)/$(PLATFORM)

OUT_CFG := $(OUT_TARGET)/$(BUILDCFG)

# Set build directory for BOOT and UPGRADE images
ifeq ($(IMG_TYPE), UPGRADE)
	SIGN_ARGS += --pad
	UPGRADE_SUFFIX :=_upgrade
	OUT_CFG := $(OUT_CFG)/upgrade
else
	OUT_CFG := $(OUT_CFG)/boot
endif

pre_build:
	$(info [PRE_BUILD] - Generating linker script for application $(CUR_APP_PATH)/linker/$(APP_NAME).ld)
	@$(CC) -E -x c $(CFLAGS) $(INCLUDE_DIRS) $(CUR_APP_PATH)/linker/$(APP_NAME)_template.ld | grep -v '^#' >$(CUR_APP_PATH)/linker/$(APP_NAME).ld

# Post build action to execute after main build job
post_build: $(OUT_CFG)/$(APP_NAME).hex
	$(info [POST_BUILD] - Executing post build script for $(APP_NAME))
# determine if target is Secure Boot - use cysecuretools for signing. built in imgtool for non secure targets
ifneq ($(filter $(PLATFORM), $(SB_PLATFORMS)),)
ifeq ($(MULTI_IMAGE), 1)
	$(PYTHON_PATH) -c "from cysecuretools import CySecureTools; tools = CySecureTools('$(CY_SEC_TOOLS_TARGET)', '$(MULTI_IMAGE_POLICY)'); tools.sign_image('$(OUT_CFG)/$(APP_NAME).hex', $(CYB_IMG_ID))"
else
	$(PYTHON_PATH) -c "from cysecuretools import CySecureTools; tools = CySecureTools('$(CY_SEC_TOOLS_TARGET)', '$(SINGLE_IMAGE_POLICY)'); tools.sign_image('$(OUT_CFG)/$(APP_NAME).hex', $(CYB_IMG_ID))"
endif
else
	mv -f $(OUT_CFG)/$(APP_NAME).hex $(OUT_CFG)/$(APP_NAME)_unsigned.hex
	$(PYTHON_PATH) $(IMGTOOL_PATH) $(SIGN_ARGS) $(OUT_CFG)/$(APP_NAME)_unsigned.hex $(OUT_CFG)/$(APP_NAME)$(UPGRADE_SUFFIX).hex
endif
