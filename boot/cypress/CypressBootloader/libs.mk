################################################################################
# \file libs.mk
# \version 1.0
#
# \brief
# Makefile to describe libraries needed for CypressBootloader applications.
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

################################################################################
# PDL library
################################################################################
PDL_VERSION = 121
#
CUR_LIBS_PATH = $(CURDIR)/libs

# Collect source files for PDL
SOURCES_PDL := $(wildcard $(CUR_LIBS_PATH)/pdl/psoc6pdl/drivers/source/*.c)

# Cy secureboot utils
SOURCES_SECBOOT_UTILS := $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_jwt/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_secure_utils/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_base64/base64/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_cjson/cJSON/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_psacrypto/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/protections/*.c)
SOURCES_SECBOOT_UTILS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/memory_val/*.c)

# PDL related include directories
INCLUDE_DIRS_PDL := $(CUR_LIBS_PATH)/pdl/psoc6pdl/drivers/include
INCLUDE_DIRS_PDL += $(CUR_LIBS_PATH)/pdl/psoc6pdl/devices/include/ip
INCLUDE_DIRS_PDL += $(CUR_LIBS_PATH)/pdl/psoc6pdl/devices/include
INCLUDE_DIRS_PDL += $(CUR_LIBS_PATH)/pdl/psoc6pdl/cmsis/include

# core-libs related include directories
INCLUDE_DIRS_CORE_LIB := $(CUR_LIBS_PATH)/core-lib/include

# Include secure bootloader utility dependencies
INCLUDE_DIRS_SECBOOT_UTILS := $(CUR_LIBS_PATH)/cy_secureboot_utils
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_jwt
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_secure_utils
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_base64
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/cy_cjson/cJSON
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/fb_mbedcrypto
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/fb_mbedcrypto/fb_cryptolib
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/fb_mbedcrypto/fb_cryptolib/crypto_driver
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/fb_mbedcrypto/fb_cryptolib/mbedtls_target
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/fb_mbedcrypto/fb_psacrypto
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_psacrypto
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/protections
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/protections/protections_config
INCLUDE_DIRS_SECBOOT_UTILS += $(CUR_LIBS_PATH)/cy_secureboot_utils/memory_val

# Collected source files for libraries
SOURCES_LIBS := $(SOURCES_PDL)
SOURCES_LIBS += $(SOURCES_PLATFORM)
SOURCES_LIBS += $(SOURCES_SECBOOT_UTILS)

# Collected include directories for libraries
INCLUDE_DIRS_LIBS := $(addprefix -I,$(INCLUDE_DIRS_PDL))
INCLUDE_DIRS_LIBS += $(addprefix -I,$(INCLUDE_DIRS_PLATFORM))
INCLUDE_DIRS_LIBS += $(addprefix -I,$(INCLUDE_DIRS_CORE_LIB))
INCLUDE_DIRS_LIBS += $(addprefix -I,$(INCLUDE_DIRS_SECBOOT_UTILS))

################################################################################
# mbedTLS settings from Flashboot
################################################################################
# MbedTLS related include directories
INCLUDE_DIRS_MBEDTLS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/inc
INCLUDE_DIRS_MBEDTLS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/inc/mbedtls
INCLUDE_DIRS_MBEDTLS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/mbed-crypto/inc
INCLUDE_DIRS_MBEDTLS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/mbed-crypto/inc/psa
INCLUDE_DIRS_MBEDTLS += $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/mbed-crypto/platform/COMPONENT_PSA_SRV_IMPL/COMPONENT_NSPE
#
INCLUDE_DIRS_LIBS += $(addprefix -I,$(INCLUDE_DIRS_MBEDTLS))
# Collect source files for MbedTLS
SOURCES_MBEDTLS := $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/src/*.c)
SOURCES_MBEDTLS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/mbed-crypto/src/*.c)
SOURCES_MBEDTLS += $(wildcard $(CUR_LIBS_PATH)/cy_secureboot_utils/flashboot_mbedtls/mbed-crypto/platform/COMPONENT_PSA_SRV_IMPL/*.c)
## mbedTLS settings

ASM_FILES_PDL :=
ifeq ($(COMPILER), GCC_ARM)
ASM_FILES_PDL += $(CUR_LIBS_PATH)/pdl/psoc6pdl/drivers/source/TOOLCHAIN_GCC_ARM/cy_syslib_gcc.S
else
$(error Only GCC ARM is supported at this moment)
endif

ASM_FILES_LIBS := $(ASM_FILES_PDL)
ASM_FILES_LIBS += $(ASM_FILES_PLATFORM)

# Add define for PDL version
DEFINES_PDL += -DPDL_VERSION=$(PDL_VERSION)

DEFINES_LIBS := $(DEFINES_PLATFORM)
DEFINES_LIBS += $(DEFINES_PDL)
