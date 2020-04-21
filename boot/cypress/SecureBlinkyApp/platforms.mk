################################################################################
# \file platforms.mk
# \version 1.0
#
# \brief
# Makefile to describe supported boards and platforms for Cypress MCUBoot-based applications.
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

# Target platform CypressBootloader is built for. PSOC_064_2M is set by default
# Supported:
#   - PSOC_064_2M
#   - PSOC_064_1M
#   - PSOC_064_512K
#   - more to come

# 512k is a priority
PLATFORM ?= PSOC_064_512K

# supported platforms
PLATFORMS := PSOC_064_2M PSOC_064_1M PSOC_064_512K

ifneq ($(filter $(PLATFORM), $(PLATFORMS)),)
else
$(error Not supported platform: '$(PLATFORM)')
endif

# For which core this application is built
# CypressBootloader may only be built for CM0p
CORE := CM0P

# Set paths for related folders
CUR_LIBS_PATH := $(CURDIR)/libs
PLATFORMS_PATH := $(CURDIR)/platforms
PLATFORM_PATH := $(PLATFORMS_PATH)/$(PLATFORM)

# MCU device selection, based on target device.
# Default chips are used for supported platforms
# This can be redefined in case of other chip usage
# TODO: this one to be moved into \platforms\%platform_name%\family.mk
ifeq ($(PLATFORM), PSOC_064_2M)
DEVICE ?= CYB0644ABZI-S2D44
PLATFORM_SUFFIX := 02
else ifeq ($(PLATFORM), PSOC_064_1M)
DEVICE ?= CYB06447BZI-BLD53
PLATFORM_SUFFIX := 01
else ifeq ($(PLATFORM), PSOC_064_512K)
DEVICE ?= CYB06445LQI-S3D42
PLATFORM_SUFFIX := 03
endif
# Additional components supported by the target
# COMPONENTS+=COMPONENT_BSP_DESIGN_MODUS
# Use CyHAL
# DEFINES:=CY_USING_HAL

# Collect C source files for PLATFORM BSP
SOURCES_PLATFORM += $(wildcard $(PLATFORMS_PATH)/*.c)
SOURCES_PLATFORM += $(wildcard $(PLATFORMS_PATH)/retarget_io_pdl/*.c)
SOURCES_PLATFORM += $(wildcard $(PLATFORM_PATH)/$(CORE)/*.c)
# Exclude system file for cm4
SOURCES_PLATFORM := $(filter-out %/system_psoc6_cm4.c, $(SOURCES_PLATFORM))

# Collect dirrectories containing headers for PLATFORM BSP
INCLUDE_DIRS_PLATFORM := $(PLATFORMS_PATH)
INCLUDE_DIRS_PLATFORM += $(PLATFORMS_PATH)/retarget_io_pdl
INCLUDE_DIRS_PLATFORM += $(PLATFORM_PATH)/$(CORE)

# Collect Assembler files for PLATFORM BSP
# Include _01_, _02_ or _03_ PLATFORM_SUFFIX depending on device family.
STARTUP_FILE := $(PLATFORM_PATH)/$(CORE)/$(COMPILER)/startup_psoc6_$(PLATFORM_SUFFIX)_cm0plus

ifeq ($(COMPILER), GCC_ARM)
	ASM_FILES_PLATFORM := $(STARTUP_FILE).S
else
$(error Only GCC ARM is supported at this moment)
endif

# Add device name from BSP makefile to defines
DEFINES += $(DEVICE)
DEFINES += $(COMPONENTS)
DEFINES += $(PLATFORM)

# Get defines from platform makefile and convert it to regular -DMY_NAME style
ifneq ($(DEFINES),)
	DEFINES_PLATFORM :=$(addprefix -D, $(subst -,_,$(DEFINES)))
endif

ifeq ($(MAKEINFO) , 1)
$(info ==============================================================================)
$(info = Platform files =)
$(info ==============================================================================)
$(info $(SOURCES_PLATFORM))
$(info $(ASM_FILES_PLATFORM))
endif
