/***************************************************************************//**
* \file main.c
* \version 1.0
*
* \brief
* Demonstrates blinking an LED under firmware control. The Cortex-CM0+ toggles
* the Red LED. The Cortex-M0+ starts the Cortex-M4 and enters sleep.
*
* Compatible Kits:
*    CY8CKIT-064S2-4343W
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

#include "system_psoc6.h"

#include "cy_pdl.h"
#include "cyhal.h"
#include "cy_retarget_io.h"

#include "cy_secure_utils.h"
#include "cy_jwt_policy.h"
#include "cy_jwt_bnu_policy.h"

#include "cyprotection.h"

#define CY_SRSS_TST_MODE_ADDR           (SRSS_BASE | 0x0100UL)
#define TST_MODE_TEST_MODE_MASK         (0x80000000UL)
#define TST_MODE_ENTERED_MAGIC          (0x12344321UL)
#define CY_SYS_CM4_PWR_CTL_KEY_OPEN     (0x05FAUL)
#define CY_BL_CM4_ROM_LOOP_ADDR         (0x16004000UL)

#define CM4_APP_HEADER_SIZE             (0x400UL)

#define MASTER_IMG_ID                   (0)

#if defined(DEBUG)

#define CY_DEBUG_UART_TX (P5_1)
#define CY_DEBUG_UART_RX (P5_0)

#if defined(PSOC_064_1M)
#warning "Check if User LED is correct for your target board."
#define LED_PORT GPIO_PRT13
#define LED_PIN 7U
#elif defined(PSOC_064_2M)
#warning "Check if User LED is correct for your target board."
#define LED_PORT GPIO_PRT1
#define LED_PIN 5U
#elif defined(PSOC_064_512K)
#warning "Check if User LED is correct for your target board."
#define LED_PORT GPIO_PRT2
#define LED_PIN 7U
#endif

#define LED_NUM 5U
#define LED_DRIVEMODE CY_GPIO_DM_STRONG_IN_OFF
#define LED_INIT_DRIVESTATE 1

const cy_stc_gpio_pin_config_t LED_config =
{
    .outVal = 1,
    .driveMode = CY_GPIO_DM_STRONG_IN_OFF,
    .hsiom = HSIOM_SEL_GPIO,
    .intEdge = CY_GPIO_INTR_DISABLE,
    .intMask = 0UL,
    .vtrip = CY_GPIO_VTRIP_CMOS,
    .slewRate = CY_GPIO_SLEW_FAST,
    .driveSel = CY_GPIO_DRIVE_FULL,
    .vregEn = 0UL,
    .ibufMode = 0UL,
    .vtripSel = 0UL,
    .vrefSel = 0UL,
    .vohSel = 0UL,
};

#endif

#define GREETING_MESSAGE          "[SecureBlinkyApp]"
#ifdef BOOT_IMG
    #define BLINK_PERIOD          (300u)
    #define CM0_TIMEOUT           (10u)
    #define GREETING_MESSAGE_VER  "[SecureBlinkyApp] SecureBlinkyApp v1.0 [CM0p]\r\n"
    #define GREETING_MESSAGE_INFO "[SecureBlinkyApp] Red led blinks SLOW for 3 sec\r\n\
[SecureBlinkyApp] Then CM4 app will be started\r\n"
#elif UPGRADE_IMG
    #define BLINK_PERIOD          (100u)
    #define CM0_TIMEOUT           (30u)
    #define GREETING_MESSAGE_VER  "[SecureBlinkyApp] SecureBlinkyApp v2.0 [+]\r\n"
    #define GREETING_MESSAGE_INFO "[SecureBlinkyApp] Red led blinks FAST for 3 sec\r\n \
[SecureBlinkyApp] Then CM4 app will be started\r\n"
#else
    #error "[SecureBlinkyApp] Please specify type of image: -DBOOT_IMG or -DUPGRADE_IMG\r\n"
#endif

/** SecureBoot policies*/
/** Boot & Upgrade policy structure */
bnu_policy_t cy_bl_bnu_policy;

/** Debug policy structure */
debug_policy_t debug_policy;

void check_result(int res)
{
    if (res != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }
}

void test_app_init_hardware(void)
{
    /* enable interrupts */
    __enable_irq();

    Cy_PDL_Init(CY_DEVICE_CFG);

    SystemCoreClockUpdate();

    /* Disabling watchdog so it will not interrupt normal flow later */
#if defined(DEBUG)
    Cy_GPIO_Pin_Init(LED_PORT, LED_PIN, &LED_config);
    /* Initialize retarget-io to use the debug UART port */
    check_result(cy_retarget_io_init(CY_DEBUG_UART_TX, CY_DEBUG_UART_RX,
                                     CY_RETARGET_IO_BAUDRATE));
#endif

    printf("\n======================================\r\n");
    printf(GREETING_MESSAGE_VER);
    printf("======================================\r\n");
    printf("\r[SecureBlinkyApp] GPIO initialized \r\n");
    printf("[SecureBlinkyApp] UART initialized \r\n");
    printf("[SecureBlinkyApp] Retarget I/O set to 115200 baudrate \r\n");
}

int main(void)
{
    uint32_t blinky_period = BLINK_PERIOD;
    uint32_t i;
    uint32_t jwtLen;
    char *jwt;
    int rc = 0;
    uint32_t app_addr = 0;

    test_app_init_hardware();

    printf(GREETING_MESSAGE_INFO);

    /* Processing of policy in JWT format */
    rc = Cy_JWT_GetProvisioningDetails(FB_POLICY_JWT, &jwt, &jwtLen);
    if(0 == rc)
    {
        rc = Cy_JWT_ParseProvisioningPacket(jwt, &cy_bl_bnu_policy, &debug_policy, MASTER_IMG_ID);
    }

    if(0 != rc)
    {
        printf("%s Policy parsing failed with code 0x%08x\n\r", GREETING_MESSAGE, rc);
    }

    app_addr = cy_bl_bnu_policy.bnu_img_policy[1].boot_area.start + CM4_APP_HEADER_SIZE;
    printf("%s CM4 app address 0x%08lx\n\r", GREETING_MESSAGE, app_addr);
    printf("%s Memory regions to protect:\n\r", GREETING_MESSAGE);
    for(i = 0; i < POLICY_MAX_N_OF_PROT_REGIONS; i++)
    {
        if(0 != cy_bl_bnu_policy.prot_regions[i].start)
        {
            printf("address: 0x%08lx; size 0x%08lx;\n\r",
                   cy_bl_bnu_policy.prot_regions[i].start,
                   (uint32_t)(1 << (cy_bl_bnu_policy.prot_regions[i].size + 1)));
        }
    }

    apply_protections();

    for (i = 0; i < CM0_TIMEOUT ; i++)
    {
        /* Toggle the user LED periodically */
        Cy_SysLib_Delay(blinky_period/2);

        /* Invert the USER LED state */
#if defined(DEBUG)
        Cy_GPIO_Inv(LED_PORT, LED_PIN);
#endif
    }
    Cy_Utils_StartAppCM4(app_addr);

    return 0;
}
