/***************************************************************************//**
* \file main.c
* \version 1.0
*
* \brief
* Demonstrates blinking an LED under firmware control. The Cortex-M4 toggles
* the Red LED. The Cortex-M0+ starts the Cortex-M4 and enters sleep.
*
* Compatible Kits:
*   CY8CKIT-062-BLE
*   CY8CKIT-062-WIFI-BT
*
* Migration to CY8CPROTO-062-4343W kit (ModusToolbox IDE):
*   1. Create this project targeting the CY8CPROTO-062-4343W kit.
*   2. Open design.modus file and replicate P0[3] configuration on P13[7]. Give
*      this pin the alias "LED_RED". Disable P0[3].
*   3. Build and Program
*
* Migration to CY8CPROTO-062-4343W kit (command line make):
*   1. Launch the Device Configurator tool from
*      ModusToolbox_1.0\tools\device-configurator-1.0\
*   2. In Device Configurator, open design.modus file
*      (ModusToolbox_1.0\libraries\psoc6sw-1.0\examples\BlinkyLED\design.modus)
*      and replicate P0[3] configuration on P13[7].
*      Give this pin the alias "LED_RED". Disable P0[3].
*   3. Perform "make clean"
*   4. Build and Program the device with "make DEVICE=CY8C624ABZI-D44 program"
*      Note that depending on the method used to program the device, you may
*      need to manually reset it by pressing the SW1 RESET button on the kit.
*   4. Observe the red blinking LED.
*   5. To switch back to CY8CKIT-062-BLE or CY8CKIT-062-WIFI-BT,
*      perform steps 1 through 3 to reconfigure the "LED_RED" to P0[3].
*      Then use "make program".
*
********************************************************************************
* \copyright
* Copyright 2017-2019 Cypress Semiconductor Corporation
* SPDX-License-Identifier: Apache-2.0
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/
#ifdef MCUBOOT_HAVE_ASSERT_H
#include "mcuboot_config/mcuboot_assert.h"
#else
#include <assert.h>
#endif

/* Cypress pdl/bsp headers */
#include "cy_pdl.h"
#include "cyhal.h"
#include "cy_retarget_io.h"
#include "cy_result.h"

#include "sysflash/sysflash.h"
#include "flash_map_backend/flash_map_backend.h"

#include "bootutil/image.h"
#include "bootutil/bootutil.h"
#include "bootutil/sign_key.h"

#include "bootutil/bootutil_log.h"

#include "cy_jwt_policy.h"
#include "cy_jwt_bnu_policy.h"

#include "cy_secure_utils.h"
#include "cy_bootloader_hw.h"
#include "cy_bootloader_version.h"
#include "cy_bootloader_services.h"

/************************************
 * CypressBootloader global defines
 * and variables.
 ************************************/
#define TOC_FREQ_8MHZ_IDX                (1UL)
#define TOC_FREQ_25MHZ_IDX               (0UL)
#define TOC_FREQ_50MHZ_IDX               (2UL)

#define TOC_LISTEN_WINDOW_0MS_IDX        (3UL)
#define TOC_LISTEN_WINDOW_1MS_IDX        (2UL)
#define TOC_LISTEN_WINDOW_10MS_IDX       (1UL)
#define TOC_LISTEN_WINDOW_20MS_IDX       (0UL)
#define TOC_LISTEN_WINDOW_100MS_IDX      (4UL)

#define CY_BOOTLOADER_IMG_ID_CM0P        (0UL)
#define CY_BOOTLOADER_IMG_ID_TEE_CM0P    (1UL)
#define CY_BOOTLOADER_IMG_ID_CYTF_CM0P   (2UL)
#define CY_BOOTLOADER_IMG_ID_OEMTF_CM0P  (3UL)
#define CY_BOOTLOADER_IMG_ID_CM4         (4UL)

#define CY_BOOTLOADER_MASTER_IMG_ID      CY_BOOTLOADER_IMG_ID_CM0P

#define CY_BOOTLOADER_SCRATCH_SIZE (0x1000)

/* TOC3 Table */
/* valid TOC3, section name cy_toc_part2 used for CRC calculation */
__attribute__((used, section(".cy_toc_part2") )) static const int cyToc[512 / 4 ] =
{
    0x200-4,                /* Object Size, bytes */
    0x01211221,             /* TOC Part 3, ID */
    0x00000000,             /* Reserved */
    0x00000000,             /* Reserved */
    CY_BOOTLOADER_START,    /* Bootloader image start address */
    0x0000FE00,             /* Bootloader image length */
    CY_BOOTLOADER_VERSION,  /* Bootloader version Major.Minor.Rev */
    CY_BOOTLOADER_BUILD,    /* Bootloader build number */
    1,                      /* Number of the next objects to add to SECURE_HASH */
    0x100FDA00,             /* TODO: it is obsoleted. Provisioning JWT string starting with length  */
    0,
    [(512 / sizeof(int)) - 2] =
    (TOC_LISTEN_WINDOW_20MS_IDX << 2) |
    (TOC_FREQ_50MHZ_IDX << 0),
};

/** SecureBoot policies*/
/** Boot & Upgrade policy structure */
bnu_policy_t cy_bl_bnu_policy;

/** Debug policy structure */
debug_policy_t debug_policy;

/* TODO: multi-image run-time config variable */
extern uint8_t boot_img_number;

#ifdef CY_FLASH_MAP_EXT_DESC
/* FlashMap descriptors */
static struct flash_area bootloader;
static struct flash_area primary_1;
static struct flash_area secondary_1;
// TODO: run-time multi-image
//#if (MCUBOOT_IMAGE_NUMBER == 2) /* if dual-image */
static struct flash_area primary_2;
static struct flash_area secondary_2;
//#endif
static struct flash_area scratch;

struct flash_area *boot_area_descs[] =
{
    &bootloader,
    &primary_1,
    &secondary_1,
    // TODO: run-time multi-image
//#if (MCUBOOT_IMAGE_NUMBER == 2) /* if dual-image */
    &primary_2,
    &secondary_2,
//#endif
    &scratch,
    NULL
};
#endif

/* Next image runner API */
static void do_boot(struct boot_rsp *rsp)
{
    uintptr_t flash_base;
    int rc;
    uint32_t app_addr = 0;

    /* The beginning of the image is the ARM vector table, containing
     * the initial stack pointer address and the reset vector
     * consecutively. Manually set the stack pointer and jump into the
     * reset vector
     */
    app_addr = (rsp->br_image_off + rsp->br_hdr->ih_hdr_size);
    BOOT_LOG_INF("Application at: 0x%08x", app_addr);

#if 0 /* need to test this */
    rc = Cy_BLServ_FreeHeap();
    assert(rc == 0);
#endif

    /* hardcode image id to run CM0p first until fwsecurity-645 merged */
    switch (cy_bl_bnu_policy.bnu_img_policy[0].id)
    {
        case CY_BOOTLOADER_IMG_ID_TEE_CM0P:
            /* Do not change protection context for CM0p SPM image with ID=1 */
            Cy_Utils_StartAppCM0p(app_addr);
            break;
        case CY_BOOTLOADER_IMG_ID_CYTF_CM0P:
        case CY_BOOTLOADER_IMG_ID_OEMTF_CM0P:
            /* Set Protection Context 2 for CM0p trusted apps with IDs 2 and 3 */
            Cy_Prot_SetActivePC(CPUSS_MS_ID_CM0, (uint32_t)CY_PROT_PC2);
            Cy_Utils_StartAppCM0p(app_addr);
            break;
        case CY_BOOTLOADER_IMG_ID_CM4:
            /* Set Protection Context 6 for CM4 application */
            Cy_Prot_SetActivePC(CPUSS_MS_ID_CM4, (uint32_t)CY_PROT_PC6);
            Cy_Utils_StartAppCM4(app_addr);
            break;
        default:
            BOOT_LOG_ERR("Unable to find bootable image");
            while (1)
            {
                __WFI() ;
            };
    }
}

/************************************
 * CypressBootloader main()
  ************************************/
int main(void)
{
    cy_rslt_t rc = !CY_RSLT_SUCCESS;
    struct boot_rsp rsp ;

#if defined(__NO_SYSTEM_INIT)
    Cy_BLServ_SystemInit();
#endif /* __NO_SYSTEM_INIT */

    /* Initialize PSOC6 specific */
    Cy_InitPSoC6_HW();
    BOOT_LOG_INF(" ");
    BOOT_LOG_INF("/******************************************************/");
    BOOT_LOG_INF(" PSoC6 CyBootloader Application %u.%u.%u.%u ",
                   CY_BOOTLOADER_MAJOR, CY_BOOTLOADER_MINOR,
                   CY_BOOTLOADER_REV, CY_BOOTLOADER_BUILD);
    BOOT_LOG_INF("/******************************************************/");
    BOOT_LOG_INF(" ");
    BOOT_LOG_INF("CypressBootloader Started");

    /* Processing of policy in JWT format */
    uint32_t jwtLen;
    char *jwt;
    rc = Cy_JWT_GetProvisioningDetails(FB_POLICY_JWT, &jwt, &jwtLen);
    if(0 == rc)
    {
        rc = Cy_JWT_ParseProvisioningPacket(jwt, &cy_bl_bnu_policy, &debug_policy,
                CY_BOOTLOADER_MASTER_IMG_ID);
    }

    // TODO: initialize SMIF if supported/requested
    // FWSECURITY-676
    if(0 != rc)
    {
        BOOT_LOG_ERR("Policy parsing failed with code 0x%08x", (int)rc);
    }
    else /*    if(0 == rc) */
    {
#if(0) /* Debug code for run-time multi-image */

        /* assume it is single- or multi-image */
        boot_img_number = 1;

        primary_1.fa_id = FLASH_AREA_IMAGE_PRIMARY(0);
        primary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        primary_1.fa_off = 0x10020000;
        primary_1.fa_size = 0x10000;

        secondary_1.fa_id = FLASH_AREA_IMAGE_SECONDARY(0);
        secondary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        secondary_1.fa_off = 0x10030000;
        secondary_1.fa_size = 0x10000;

        primary_2.fa_id = FLASH_AREA_IMAGE_PRIMARY(1);
        primary_2.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        primary_2.fa_off = 0x10040000;
        primary_2.fa_size = 0x10000;

        secondary_2.fa_id = FLASH_AREA_IMAGE_SECONDARY(1);
        secondary_2.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        secondary_2.fa_off = 0x10050000;
        secondary_2.fa_size = 0x10000;

        bootloader.fa_id = FLASH_AREA_BOOTLOADER;
        bootloader.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        bootloader.fa_off = 0x101D0000;
        bootloader.fa_size = 0x10000;

        scratch.fa_id = FLASH_AREA_IMAGE_SCRATCH;
        scratch.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        scratch.fa_off = 0x10060000;
        scratch.fa_size = 0x1000;
#else
            /* assume single-image is requested by policy */
        boot_img_number = 1;

        primary_1.fa_id = FLASH_AREA_IMAGE_PRIMARY(0);
        primary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

        primary_1.fa_off = cy_bl_bnu_policy.bnu_img_policy[0].boot_area.start;
        primary_1.fa_size = cy_bl_bnu_policy.bnu_img_policy[0].boot_area.size;

        secondary_1.fa_id = FLASH_AREA_IMAGE_SECONDARY(0);
        secondary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

        secondary_1.fa_off = cy_bl_bnu_policy.bnu_img_policy[0].upgrade_area.start;
        secondary_1.fa_size = cy_bl_bnu_policy.bnu_img_policy[0].upgrade_area.size;

        if((cy_bl_bnu_policy.bnu_img_policy[0].multi_image == 1) &&
            (cy_bl_bnu_policy.bnu_img_policy[1].multi_image == 2))
        {
            boot_img_number = 2;

            primary_2.fa_id = FLASH_AREA_IMAGE_PRIMARY(1);
            primary_2.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

            primary_2.fa_off = cy_bl_bnu_policy.bnu_img_policy[1].boot_area.start;
            primary_2.fa_size = cy_bl_bnu_policy.bnu_img_policy[1].boot_area.size;

            secondary_2.fa_id = FLASH_AREA_IMAGE_SECONDARY(1);
            secondary_2.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

            secondary_2.fa_off = cy_bl_bnu_policy.bnu_img_policy[1].upgrade_area.start;
            secondary_2.fa_size = cy_bl_bnu_policy.bnu_img_policy[1].upgrade_area.size;

            BOOT_LOG_INF("Enabled multi-image N = %d:", boot_img_number);
        }
        else{
            BOOT_LOG_INF("Single-image N = %d:", boot_img_number);
        }
            /* add bootloader */
        bootloader.fa_id = FLASH_AREA_BOOTLOADER;
        bootloader.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        bootloader.fa_off = cyToc[4];
        bootloader.fa_size = cyToc[5];
            /* initialize scratch */
        scratch.fa_id = FLASH_AREA_IMAGE_SCRATCH;
        scratch.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        scratch.fa_off = bootloader.fa_off - CY_BOOTLOADER_SCRATCH_SIZE;
        scratch.fa_size = CY_BOOTLOADER_SCRATCH_SIZE;

        // TODO: apply protections if supported/requested
#endif
    }

    rc = boot_go(&rsp);
    if(rc == 0)
    {
        BOOT_LOG_INF("User Application validated successfully");
        do_boot(&rsp);
    }
    else
    {
        BOOT_LOG_INF("CypressBootloader found none of bootable images") ;
        Cy_BLServ_Assert(0 == rc);
    }

    return 0;
}
