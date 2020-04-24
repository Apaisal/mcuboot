/***************************************************************************//**
* \file cy_bootloader_hw.c
* \version 1.0
*
* \brief
*  This is the source code implementation file for bootloader hardware layer.
*
********************************************************************************
* \copyright
* Copyright 2019, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/
#include "cycfg_clocks.h"
#include "cycfg_peripherals.h"
#include "cycfg_pins.h"
#include "cycfg_routing.h"

#include "cy_pdl.h"
#include "cy_retarget_io_pdl.h"
#include "cy_result.h"
#include "cy_device_headers.h"
#include "cy_wdt.h"

#include "cy_bootloader_hw.h"

#include "mcuboot_config/mcuboot_logging.h"

#include "cy_scb_uart.h"
#include "cy_sysclk.h"

extern void __enable_irq();

#if defined(CY_BOOTLOADER_DIAGNOSTIC_GPIO)
#define LED_RED_NUM 5U
#define LED_RED_DRIVEMODE CY_GPIO_DM_STRONG_IN_OFF
#define LED_RED_INIT_DRIVESTATE 1
#ifndef ioss_0_port_1_pin_5_HSIOM
	#define ioss_0_port_1_pin_5_HSIOM HSIOM_SEL_GPIO
#endif
#define LED_RED_HSIOM ioss_0_port_1_pin_5_HSIOM
#define LED_RED_IRQ ioss_interrupts_gpio_0_IRQn

const cy_stc_gpio_pin_config_t LED_RED_config =
{
    .outVal = 1,
    .driveMode = CY_GPIO_DM_STRONG_IN_OFF,
    .hsiom = LED_RED_HSIOM,
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
#endif /* CY_BOOTLOADER_DIAGNOSTIC_GPIO */

void Cy_InitPSoC6_HW(void)
{
    init_cycfg_clocks();
    init_cycfg_peripherals();
    init_cycfg_pins();

    /* enable interrupts */
    __enable_irq();

    /* Disabling watchdog so it will not interrupt normal flow later */
    Cy_WDT_Unlock();
    Cy_WDT_Disable();

#if (MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF)
#if defined(CY_BOOTLOADER_DIAGNOSTIC_GPIO)
    Cy_GPIO_Pin_Init(LED_RED_PORT, LED_RED_PIN, &LED_RED_config);
#endif

    /* Initialize retarget-io to use the debug UART port (CYBSP_UART_HW) */
    cy_retarget_io_pdl_init(115200u);

#endif
}
