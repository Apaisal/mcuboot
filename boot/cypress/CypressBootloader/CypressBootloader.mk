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
# Set default compiler to GCC if not specified from command line
COMPILER ?= GCC_ARM

ifneq ($(COMPILER), GCC_ARM)
$(error Only GCC ARM is supported at this moment)
endif

CUR_APP_PATH = $(CURDIR)/$(APP_NAME)

CY_BOOTLOADER_LOG_LEVEL ?= MCUBOOT_LOG_LEVEL_INFO

CY_BOOTLOADER_MAJOR ?= 1
CY_BOOTLOADER_MINOR ?= 1
CY_BOOTLOADER_REV ?= 0
CY_BOOTLOADER_BUILD ?= 111

include $(CUR_APP_PATH)/platforms.mk
include $(CUR_APP_PATH)/libs.mk
include $(CUR_APP_PATH)/toolchains.mk

# Application-specific DEFINES
DEFINES_APP := -DMBEDTLS_CONFIG_FILE="\"mcuboot_crypto_config.h\""
DEFINES_APP += -DECC256_KEY_FILE="\"keys/$(SIGN_KEY_FILE).pub\""
DEFINES_APP += -DCORE=$(CORE)

# Add start address for each target device, since flash size is different
#
# Define maximum image sectors number, considering maximum slot size
# equal to all available flash for BOOT slot. it is assumed that UPGRADE
# slot in this case is located in External Memory
ifeq ($(PLATFORM), PSOC_064_2M)
CY_BOOTLOADER_APP_START ?= 0x101D0000
# 0x1D0000 max slot size
DEFINES_APP += -DMCUBOOT_MAX_IMG_SECTORS=3712
CY_SEC_TOOLS_TARGET := cyb06xxa
else ifeq ($(PLATFORM), PSOC_064_1M)
CY_BOOTLOADER_APP_START ?= 0x100D0000
# 0xD0000 max slot size
DEFINES_APP += -DMCUBOOT_MAX_IMG_SECTORS=1664
CY_SEC_TOOLS_TARGET := cyb06xx7
else ifeq ($(PLATFORM), PSOC_064_512K)
CY_BOOTLOADER_APP_START ?= 0x10030000
# 0x30000 slot size
DEFINES_APP += -DMCUBOOT_MAX_IMG_SECTORS=384
CY_SEC_TOOLS_TARGET := cyb06xx5
else
$(error "Not suppoted target name $(PLATFORM)")
endif

# Overwite path to linker script if custom is required, otherwise platform default is used
ifeq ($(COMPILER), GCC_ARM)
LINKER_SCRIPT := $(CUR_APP_PATH)/linker/$(APP_NAME)_$(PLATFORM).ld
else
$(error Only GCC ARM is supported at this moment)
endif

# Define maximum Cybootloader image size
ifeq ($(MAKEINFO), 1)
CY_BOOTLOADER_APP_START=$(shell cat $(LINKER_SCRIPT) | grep '^CY_BOOTLOADER_START' | sed -e 's/^.*\(0[xX][0-9a-fA-F]*\)[^0-9a-fA-F].*$\/\1/')
CY_PROTECTED_DATA_START=$(shell cat $(LINKER_SCRIPT) | grep '^CY_PROTECTED_DATA_START' | sed -e 's/^.*\(0[xX][0-9a-fA-F]*\)[^0-9a-fA-F].*$\/\1/')
CY_BOOTLOADER_START=$(shell printf "%d" $(CY_BOOTLOADER_APP_START))
CY_PROTECTEDD_START=$(shell printf "%d" $(CY_PROTECTED_DATA_START))
CY_BOOTLOADER_SIZE=$(shell expr $(CY_PROTECTEDD_START) - $(CY_BOOTLOADER_START) )
# TODO: Add additional checking and debug information
# $(info CY_BOOTLOADER_APP_SIZE = $(CY_BOOTLOADER_SIZE))
endif

# multi-image setup ?
DEFINES_APP += -DMCUBOOT_IMAGE_NUMBER=2

# Use external flash map descriptors since flash map is driven by policy
DEFINES_APP += -DCY_FLASH_MAP_EXT_DESC
DEFINES_APP += -DCY_BOOTLOADER_START=$(CY_BOOTLOADER_APP_START)
DEFINES_APP += -DCY_BOOTLOADER_SIZE=$(CY_BOOTLOADER_APP_SIZE)
DEFINES_APP += -D__NO_SYSTEM_INIT
DEFINES_APP += -DCY_BOOTLOADER_DIAGNOSTIC_GPIO
DEFINES_APP += $(DEFINES_USER)
DEFINES_APP += -D$(BUILDCFG)
DEFINES_APP += -D$(APP_NAME)

ifdef ($(CY_BOOT_USE_EXTERNAL_FLASH))
$(info Enable external memory support (SMIF))
DEFINES_APP += -DCY_BOOT_USE_EXTERNAL_FLASH
endif

ifeq ($(BUILDCFG), Debug)
DEFINES_APP += -DMCUBOOT_LOG_LEVEL=$(CY_BOOTLOADER_LOG_LEVEL)
DEFINES_APP += -DMCUBOOT_HAVE_LOGGING
DEFINES_APP += -DCY_SECURE_UTILS_LOG
else
	ifeq ($(BUILDCFG), Release)
		DEFINES_APP += -DMCUBOOT_LOG_LEVEL=MCUBOOT_LOG_LEVEL_OFF
#		DEFINES_APP += -DNDEBUG
	else
		$(error "Not supported build configuration : $(BUILDCFG)")
	endif
endif

# TODO: MCUBoot library
# Collect MCUBoot sourses
SRC_FILES_MCUBOOT := bootutil_misc.c caps.c loader.c tlv.c swap_scratch.c
SOURCES_MCUBOOT := $(addprefix $(CURDIR)/../bootutil/src/, $(SRC_FILES_MCUBOOT))

# Collect CypresBootloader Application sources
SOURCES_APP_SRC := $(wildcard $(CUR_APP_PATH)/source/*.c)
# Collect Flash Layer port sources
SOURCES_FLASH_PORT := $(wildcard $(CURDIR)/cy_flash_pal/*.c)
SOURCES_FLASH_PORT += $(wildcard $(CURDIR)/cy_flash_pal/flash_qspi/*.c)

# Collect all the sources
SOURCES_APP := $(SOURCES_MCUBOOT)
SOURCES_APP += $(SOURCES_APP_SRC)
SOURCES_APP += $(SOURCES_FLASH_PORT)

INCLUDES_DIRS_MCUBOOT := $(addprefix -I, $(CURDIR)/../bootutil/include)
INCLUDES_DIRS_MCUBOOT += $(addprefix -I, $(CURDIR)/../bootutil/src)

INCLUDE_DIRS_APP := $(addprefix -I, $(CURDIR))
INCLUDE_DIRS_APP += $(addprefix -I, $(CURDIR)/cy_flash_pal/include)
INCLUDE_DIRS_APP += $(addprefix -I, $(CURDIR)/cy_flash_pal/flash_qspi)
INCLUDE_DIRS_APP += $(addprefix -I, $(CURDIR)/cy_flash_pal/include/flash_map_backend)
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH))
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH)/config)
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH)/os)
INCLUDE_DIRS_APP += $(addprefix -I, $(CUR_APP_PATH)/source)

INCLUDE_FILES_MCUBOOT := bootutil_priv.h

INCLUDE_FILES_APP := $(addprefix $(CURDIR)/../bootutil/src/, $(INCLUDE_FILES_MCUBOOT))

# Output folder
OUT := $(APP_NAME)/out
# Output folder to contain build artifacts
OUT_PLATFORM := $(OUT)/$(PLATFORM)

OUT_CFG := $(OUT_PLATFORM)/$(BUILDCFG)

# Set path to cypress key for certificate generation
# Production version of CypressBootloader will be signed by Cypress Private Key
CERT_KEY ?= $(CY_SEC_TOOLS_PATH)/cysecuretools/targets/common/prebuilt/oem_state.json

# Post build action to execute after main build job
post_build: $(OUT_CFG)/$(APP_NAME).hex
	$(GCC_PATH)/bin/arm-none-eabi-objcopy --change-addresses=$(HEADER_OFFSET) -O ihex $(OUT_CFG)/$(APP_NAME).elf $(OUT_CFG)/$(APP_NAME)_CM0p.hex
ifeq ($(MAKEINFO), 1)
	$(eval CYBOOT_SIZE = $(shell $(GCC_PATH)/bin/arm-none-eabi-size -t $(OUT_APP)/$(APP_NAME).hex | grep TOTAL | sed -e 's/^[^0-9]*\([0-9]*\)[^0-9]*\([0-9]*\)[^0-9]*.*$\/\2/'))
	$(eval CYBOOT_UNUSED = $(shell expr $(CY_BOOTLOADER_SIZE) - $(CYBOOT_SIZE)))
	$(info  )
	$(info *****************************************************)
	$(info ***   Bootloader  allocated space = $(CY_BOOTLOADER_SIZE) bytes   ***)
	$(info *** --------------------------------------------- ***)
	$(info ***   Bootloader total image size = $(CYBOOT_SIZE) bytes   ***)
	$(info *****************************************************)
	$(info ***                                               ***)
	$(info ***   Bootloader   UNUSED   space = $(CYBOOT_UNUSED) bytes   ***)
	$(info ***                                               ***)
	$(info *****************************************************)
	$(info  )
endif
ifeq ($(POST_BUILD), 1)
	$(info [POST_BUILD] - Creating image certificate for $(APP_NAME))
	cysecuretools -t $(CY_SEC_TOOLS_TARGET) image-certificate -i $(OUT_CFG)/$(APP_NAME)_CM0p.hex -k $(CERT_KEY) -o $(OUT_CFG)/$(APP_NAME)_CM0p.jwt -v '${CY_BOOTLOADER_MAJOR}.${CY_BOOTLOADER_MINOR}.${CY_BOOTLOADER_REV}.${CY_BOOTLOADER_BUILD}'
endif
ASM_FILES_APP :=
