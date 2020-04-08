/***************************************************************************//**
* \file cy_bootloader_hw.h
* \version 1.0
*
* \brief
*  This is the header file implementation file for bootloader hardware layer.
*
********************************************************************************
* \copyright
* Copyright 2019, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#ifndef SOURCE_CY_BOOTLOADER_HW_H_
#define SOURCE_CY_BOOTLOADER_HW_H_

#include "cy_gpio.h"
#include "cy_scb_uart.h"
#include "cy_sysclk.h"

#if defined(CY8C6245LQI_S3D72)
#define LED_RED_PORT GPIO_PRT0
#define LED_RED_PIN 2U
#else
#define LED_RED_PORT GPIO_PRT1
#define LED_RED_PIN 0U // TODO: PSVP LED
#endif

#define QSPI_SS_ENABLED 1U
#define QSPI_SS_PORT GPIO_PRT11
#define QSPI_SS_PORT_NUM 11U
#define QSPI_SS_PIN 2U
#define QSPI_SS_NUM 2U
#define QSPI_SS_DRIVEMODE CY_GPIO_DM_STRONG_IN_OFF
#define QSPI_SS_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_2_HSIOM
    #define ioss_0_port_11_pin_2_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_SS_HSIOM ioss_0_port_11_pin_2_HSIOM
#define QSPI_SS_IRQ ioss_interrupts_gpio_11_IRQn
#define QSPI_DATA3_ENABLED 1U
#define QSPI_DATA3_PORT GPIO_PRT11
#define QSPI_DATA3_PORT_NUM 11U
#define QSPI_DATA3_PIN 3U
#define QSPI_DATA3_NUM 3U
#define QSPI_DATA3_DRIVEMODE CY_GPIO_DM_STRONG
#define QSPI_DATA3_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_3_HSIOM
    #define ioss_0_port_11_pin_3_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_DATA3_HSIOM ioss_0_port_11_pin_3_HSIOM
#define QSPI_DATA3_IRQ ioss_interrupts_gpio_11_IRQn
#define QSPI_DATA2_ENABLED 1U
#define QSPI_DATA2_PORT GPIO_PRT11
#define QSPI_DATA2_PORT_NUM 11U
#define QSPI_DATA2_PIN 4U
#define QSPI_DATA2_NUM 4U
#define QSPI_DATA2_DRIVEMODE CY_GPIO_DM_STRONG
#define QSPI_DATA2_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_4_HSIOM
    #define ioss_0_port_11_pin_4_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_DATA2_HSIOM ioss_0_port_11_pin_4_HSIOM
#define QSPI_DATA2_IRQ ioss_interrupts_gpio_11_IRQn
#define QSPI_DATA1_ENABLED 1U
#define QSPI_DATA1_PORT GPIO_PRT11
#define QSPI_DATA1_PORT_NUM 11U
#define QSPI_DATA1_PIN 5U
#define QSPI_DATA1_NUM 5U
#define QSPI_DATA1_DRIVEMODE CY_GPIO_DM_STRONG
#define QSPI_DATA1_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_5_HSIOM
    #define ioss_0_port_11_pin_5_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_DATA1_HSIOM ioss_0_port_11_pin_5_HSIOM
#define QSPI_DATA1_IRQ ioss_interrupts_gpio_11_IRQn
#define QSPI_DATA0_ENABLED 1U
#define QSPI_DATA0_PORT GPIO_PRT11
#define QSPI_DATA0_PORT_NUM 11U
#define QSPI_DATA0_PIN 6U
#define QSPI_DATA0_NUM 6U
#define QSPI_DATA0_DRIVEMODE CY_GPIO_DM_STRONG
#define QSPI_DATA0_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_6_HSIOM
    #define ioss_0_port_11_pin_6_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_DATA0_HSIOM ioss_0_port_11_pin_6_HSIOM
#define QSPI_DATA0_IRQ ioss_interrupts_gpio_11_IRQn
#define QSPI_SPI_CLOCK_ENABLED 1U
#define QSPI_SPI_CLOCK_PORT GPIO_PRT11
#define QSPI_SPI_CLOCK_PORT_NUM 11U
#define QSPI_SPI_CLOCK_PIN 7U
#define QSPI_SPI_CLOCK_NUM 7U
#define QSPI_SPI_CLOCK_DRIVEMODE CY_GPIO_DM_STRONG_IN_OFF
#define QSPI_SPI_CLOCK_INIT_DRIVESTATE 1
#ifndef ioss_0_port_11_pin_7_HSIOM
    #define ioss_0_port_11_pin_7_HSIOM HSIOM_SEL_GPIO
#endif
#define QSPI_SPI_CLOCK_HSIOM ioss_0_port_11_pin_7_HSIOM
#define QSPI_SPI_CLOCK_IRQ ioss_interrupts_gpio_11_IRQn

#define QSPI_ENABLED 1U
#define QSPI_HW SMIF0
#define QSPI_IRQ smif_interrupt_IRQn
#define QSPI_MEMORY_MODE_ALIGMENT_ERROR (0UL)
#define QSPI_RX_DATA_FIFO_UNDERFLOW (0UL)
#define QSPI_TX_COMMAND_FIFO_OVERFLOW (0UL)
#define QSPI_TX_DATA_FIFO_OVERFLOW (0UL)
#define QSPI_RX_FIFO_TRIGEER_LEVEL (0UL)
#define QSPI_TX_FIFO_TRIGEER_LEVEL (0UL)
#define QSPI_DATALINES0_1 (1UL)
#define QSPI_DATALINES2_3 (1UL)
#define QSPI_DATALINES4_5 (0UL)
#define QSPI_DATALINES6_7 (0UL)
#define QSPI_SS0 (1UL)
#define QSPI_SS1 (0UL)
#define QSPI_SS2 (0UL)
#define QSPI_SS3 (0UL)
#define QSPI_DESELECT_DELAY 7

extern const cy_stc_gpio_pin_config_t QSPI_SS_config;
extern const cy_stc_gpio_pin_config_t QSPI_DATA3_config;
extern const cy_stc_gpio_pin_config_t QSPI_DATA2_config;
extern const cy_stc_gpio_pin_config_t QSPI_DATA1_config;
extern const cy_stc_gpio_pin_config_t QSPI_DATA0_config;
extern const cy_stc_gpio_pin_config_t QSPI_SPI_CLOCK_config;

void Cy_InitPSoC6_HW(void);

#endif /* SOURCE_CY_BOOTLOADER_HW_H_ */
