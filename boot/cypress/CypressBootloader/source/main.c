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
#include "cy_result.h"

#include "sysflash/sysflash.h"
#include "flash_map_backend/flash_map_backend.h"
#include "flash_qspi.h"

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

#define CY_BOOTLOADER_SMIF_SFDP_MAX (0x4)
#define CY_BOOTLOADER_SMIF_CFG  (0x2)

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

/* This function is required by Cy_Utils_StartAppCM4() */
void AppSystemInit(void)
{
#if defined(__NO_SYSTEM_INIT)
    Cy_BLServ_SystemInit();
#else
    SystemInit();
#endif /* __NO_SYSTEM_INIT */
}

/* Next image runner API */
static void do_boot(struct boot_rsp *rsp)
{
    static uint32_t app_addr = 0;
    uint32_t en_acq = 1;
    register uint32_t application_start;

    /* The beginning of the image is the ARM vector table, containing
     * the initial stack pointer address and the reset vector
     * consecutively. Manually set the stack pointer and jump into the
     * reset vector
     */
    application_start = (rsp->br_image_off + rsp->br_hdr->ih_hdr_size);
    BOOT_LOG_INF("Application at: 0x%08lx", application_start);

    if((cy_bl_bnu_policy.bnu_img_policy[0].multi_image == 1) &&
        (cy_bl_bnu_policy.bnu_img_policy[1].multi_image == 2))
    {
        en_acq = 0;
        BOOT_LOG_INF("Acquiring is disabled");
    }

    /* hardcode image id to run CM0p first until fwsecurity-645 merged */
    switch (cy_bl_bnu_policy.bnu_img_policy[0].id)
    {
        case CY_BOOTLOADER_IMG_ID_TEE_CM0P:
            /* Do not change protection context for CM0p SPM image with ID=1 */
            Cy_Utils_StartAppCM0p(application_start, en_acq);
            break;
        case CY_BOOTLOADER_IMG_ID_CYTF_CM0P:
        case CY_BOOTLOADER_IMG_ID_OEMTF_CM0P:
            /* Set Protection Context 2 for CM0p trusted apps with IDs 2 and 3 */
            Cy_Prot_SetActivePC(CPUSS_MS_ID_CM0, (uint32_t)CY_PROT_PC2);
            Cy_Utils_StartAppCM0p(application_start, en_acq);
            break;
        case CY_BOOTLOADER_IMG_ID_CM4:
            /* Set Protection Context 6 for CM4 application */
            Cy_Prot_SetActivePC(CPUSS_MS_ID_CM4, (uint32_t)CY_PROT_PC6);
            Cy_Utils_CleanSecureAppRam(application_start, &app_addr);
            Cy_Utils_StartAppCM4(application_start, false);
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
* Apply Policies
***********************************/
void Cy_Bl_ApplyPolicy(void)
{
    primary_1.fa_id = FLASH_AREA_IMAGE_PRIMARY(0);
    primary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

    primary_1.fa_off = cy_bl_bnu_policy.bnu_img_policy[0].boot_area.start;
    primary_1.fa_size = cy_bl_bnu_policy.bnu_img_policy[0].boot_area.size;

    secondary_1.fa_id = FLASH_AREA_IMAGE_SECONDARY(0);
    secondary_1.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;

#ifdef CY_BOOT_USE_EXTERNAL_FLASH
        /* check if upgrade slot is requested from external memory */
    if(cy_bl_bnu_policy.bnu_img_policy[0].smif_id != 0)
    {
        secondary_1.fa_device_id = FLASH_DEVICE_EXTERNAL_FLAG;
        BOOT_LOG_INF("Secondary Slot 1 will upgrade from External Memory");
    }
#endif
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

#ifdef CY_BOOT_USE_EXTERNAL_FLASH
            /* check if upgrade slot is requested from external memory */
        if(cy_bl_bnu_policy.bnu_img_policy[1].smif_id != 0)
        {
            secondary_2.fa_device_id = FLASH_DEVICE_EXTERNAL_FLAG;
            BOOT_LOG_INF("Secondary Slot 2 will upgrade from External Memory");
        }
#endif
        secondary_2.fa_off = cy_bl_bnu_policy.bnu_img_policy[1].upgrade_area.start;
        secondary_2.fa_size = cy_bl_bnu_policy.bnu_img_policy[1].upgrade_area.size;

        BOOT_LOG_INF("Enabled multi-image N = %d:", boot_img_number);
    }
    else{
        BOOT_LOG_INF("Single-image N = %d:", boot_img_number);
    }
}

/************************************
* Initialize External Memory Module
***********************************/
int Cy_Bl_InitSMIF(void)
{
    int rc = 0;
    uint32_t smif_id = 0;
    cy_stc_smif_block_config_t *smifConfigPtr;

        /* initialize SMIF if at least one secondary slot requires it */
    if(cy_bl_bnu_policy.bnu_img_policy[0].smif_id != 0)
    {
        smif_id = cy_bl_bnu_policy.bnu_img_policy[0].smif_id;
    }
        /* OR */
    if(cy_bl_bnu_policy.bnu_img_policy[1].smif_id != 0)
    {
        smif_id = cy_bl_bnu_policy.bnu_img_policy[1].smif_id;
    }
        /* if at least one secondary requires SMIF */
    if(smif_id != 0)
    {
        /* if (SFDP) */
        if(smif_id <= CY_BOOTLOADER_SMIF_SFDP_MAX)
        {
            rc = qspi_init_sfdp(smif_id);
            if(rc == 0)
            {
                BOOT_LOG_INF("External Memory initialized w/ SFDP.");
            }
            else
            {
                BOOT_LOG_ERR("External Memory initialization w/ SFDP FAILED: 0x%02x", rc);
            }
        }
        /* Not Supported yet */
/*        else
        if(smif_id == TBD)
        {
            smifConfigPtr = &smifBlockConfig;
            rc = qspi_init(smifConfigPtr);
            if(rc == 0)
            {
                BOOT_LOG_INF("External Memory initialized w/ Flash Config.");
            }
            else
            {
                BOOT_LOG_ERR("External Memory initialization w/ Flash Config FAILED: 0x%02x", rc);
            }
        } */
    }
    return rc;
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
        /* BOOT_LOG_INF("Provisioning packet : %s", jwt); */
        rc = Cy_JWT_ParseProvisioningPacket(jwt, &cy_bl_bnu_policy, &debug_policy,
                CY_BOOTLOADER_MASTER_IMG_ID);
    }
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
            /* Apply policy data to flash map and external memory IF */
        Cy_Bl_ApplyPolicy();
            /* add bootloader */
        bootloader.fa_id = FLASH_AREA_BOOTLOADER;
        bootloader.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        bootloader.fa_off = CY_BOOTLOADER_START;
        bootloader.fa_size = 0x10000;
            /* initialize scratch */
        scratch.fa_id = FLASH_AREA_IMAGE_SCRATCH;
        scratch.fa_device_id = FLASH_DEVICE_INTERNAL_FLASH;
        scratch.fa_off = bootloader.fa_off - CY_BOOTLOADER_SCRATCH_SIZE;
        scratch.fa_size = CY_BOOTLOADER_SCRATCH_SIZE;

#ifdef CY_BOOT_USE_EXTERNAL_FLASH
        /* if supported/requested */
        if(Cy_Bl_InitSMIF() != 0)
        {   /* SMIF initialization failed, disallow upgrade */
            if(cy_bl_bnu_policy.bnu_img_policy[0].smif_id != 0)
            {
                cy_bl_bnu_policy.bnu_img_policy[0].upgrade = false;
            }
                /* OR */
            if(cy_bl_bnu_policy.bnu_img_policy[1].smif_id != 0)
            {
                cy_bl_bnu_policy.bnu_img_policy[1].upgrade = false;
            }
        }
#endif

        cy_en_prot_status_t prot_ret_code = apply_protections();
        if(prot_ret_code != CY_PROT_SUCCESS)
        {
            BOOT_LOG_INF("CypressBootloader failed to apply protection settings, error = 0x%X", prot_ret_code) ;
            Cy_BLServ_Assert(0);
        }
#endif
    }

    if(rc == 0)
    {
        rc = boot_go(&rsp);
    }

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
