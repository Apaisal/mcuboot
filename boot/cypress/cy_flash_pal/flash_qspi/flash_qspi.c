/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/***************************************************************************//**
* \file flash_qspi.c
* \version 1.0
*
* \brief
*  This is the source file of external flash driver adaptation layer between PSoC6
*  and standard MCUBoot code.
*
********************************************************************************
* \copyright
*
* (c) 2020, Cypress Semiconductor Corporation
* or a subsidiary of Cypress Semiconductor Corporation. All rights
* reserved.
*
* This software, including source code, documentation and related
* materials ("Software"), is owned by Cypress Semiconductor
* Corporation or one of its subsidiaries ("Cypress") and is protected by
* and subject to worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-
* exclusive, non-transferable license to copy, modify, and compile the
* Software source code solely for use in connection with Cypress?s
* integrated circuit products. Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO
* WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING,
* BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE. Cypress reserves the right to make
* changes to the Software without notice. Cypress does not assume any
* liability arising out of the application or use of the Software or any
* product or circuit described in the Software. Cypress does not
* authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*
******************************************************************************/
#include "cy_pdl.h"
#include <stdio.h>
#include "flash_qspi.h"

#define CY_SMIF_SYSCLK_HFCLK_DIVIDER     CY_SYSCLK_CLKHF_DIVIDE_BY_4

#define SMIF_TRANSFER_TIMEOUT       (1000UL) /* The timeout (microseconds) to use in polling of
                                             * the transfer status of the SMIF block
                                             */

/* This is the board specific stuff that should align with your board.
 *
 * QSPI resources:
 *
 * SS0  - P11_2
 * SS1  - P11_1
 * SS2  - P11_0
 * SS3  - P12_4
 *
 * D3  - P11_3
 * D2  - P11_4
 * D1  - P11_5
 * D0  - P11_6
 *
 * SCK - P11_7
 *
 * SMIF Block - SMIF0
 *
 */

/* SMIF SlaveSelect Configurations */
struct qspi_ss_config
{
    GPIO_PRT_Type* SS_Port;
    int SS_Pin;
    en_hsiom_sel_t SS_Mux;
};

#if (defined(PSOC_064_2M) || defined(PSOC_064_1M))
    #define CY_BOOTLOADER_SMIF_SS_CFG_NUM 4
#elif defined(PSOC_064_512K)
    #define CY_BOOTLOADER_SMIF_SS_CFG_NUM 3
#else
#error "Platform device name is unsupported."
#endif
struct qspi_ss_config qspi_SS_Configuration[CY_BOOTLOADER_SMIF_SS_CFG_NUM] =
{
    {
        .SS_Port = GPIO_PRT11,
        .SS_Pin = 2,
        .SS_Mux = P11_2_SMIF_SPI_SELECT0
    },
    {
        .SS_Port = GPIO_PRT11,
        .SS_Pin = 1,
        .SS_Mux = P11_1_SMIF_SPI_SELECT1
    },
    {
        .SS_Port = GPIO_PRT11,
        .SS_Pin = 0,
        .SS_Mux = P11_0_SMIF_SPI_SELECT2
    },
#if(CY_BOOTLOADER_SMIF_SS_CFG_NUM > 3)
    {
        .SS_Port = GPIO_PRT12,
        .SS_Pin = 4,
        .SS_Mux = P12_4_SMIF_SPI_SELECT3
    }
#endif
};

static GPIO_PRT_Type *D3Port = GPIO_PRT11;
static int D3Pin = 3;
static en_hsiom_sel_t D3MuxPort = P11_3_SMIF_SPI_DATA3;

static GPIO_PRT_Type *D2Port = GPIO_PRT11;
static int D2Pin = 4;
static en_hsiom_sel_t D2MuxPort = P11_4_SMIF_SPI_DATA2;

static GPIO_PRT_Type *D1Port = GPIO_PRT11;
static int D1Pin = 5;
static en_hsiom_sel_t D1MuxPort = P11_5_SMIF_SPI_DATA1;

static GPIO_PRT_Type *D0Port = GPIO_PRT11;
static int D0Pin = 6;
static en_hsiom_sel_t D0MuxPort = P11_6_SMIF_SPI_DATA0;

static GPIO_PRT_Type *SCKPort = GPIO_PRT11;
static int SCKPin = 7;
static en_hsiom_sel_t SCKMuxPort = P11_7_SMIF_SPI_CLK;

static SMIF_Type *QSPIPort  = SMIF0;

cy_stc_smif_mem_cmd_t sfdpcmd =
{
    .command = 0x5A,
    .cmdWidth = CY_SMIF_WIDTH_SINGLE,
    .addrWidth = CY_SMIF_WIDTH_SINGLE,
    .mode = 0xFFFFFFFFU,
    .dummyCycles = 8,
    .dataWidth = CY_SMIF_WIDTH_SINGLE,
};

static cy_stc_smif_mem_cmd_t rdcmd0;
static cy_stc_smif_mem_cmd_t wrencmd0;
static cy_stc_smif_mem_cmd_t wrdiscmd0;
static cy_stc_smif_mem_cmd_t erasecmd0;
static cy_stc_smif_mem_cmd_t chiperasecmd0;
static cy_stc_smif_mem_cmd_t pgmcmd0;
static cy_stc_smif_mem_cmd_t readsts0;
static cy_stc_smif_mem_cmd_t readstsqecmd0;
static cy_stc_smif_mem_cmd_t writestseqcmd0;

static cy_stc_smif_mem_device_cfg_t dev_sfdp_0 =
{
    .numOfAddrBytes = 4,
    .readSfdpCmd = &sfdpcmd,
    .readCmd = &rdcmd0,
    .writeEnCmd = &wrencmd0,
    .writeDisCmd = &wrdiscmd0,
    .programCmd = &pgmcmd0,
    .eraseCmd = &erasecmd0,
    .chipEraseCmd = &chiperasecmd0,
    .readStsRegWipCmd = &readsts0,
    .readStsRegQeCmd = &readstsqecmd0,
    .writeStsRegQeCmd = &writestseqcmd0,
};

static cy_stc_smif_mem_config_t mem_sfdp_0 =
{
    /* The base address the memory slave is mapped to in the PSoC memory map.
    Valid when the memory-mapped mode is enabled. */
    .baseAddress = 0x18000000U,
    /* The size allocated in the PSoC memory map, for the memory slave device.
    The size is allocated from the base address. Valid when the memory mapped mode is enabled. */
/*    .memMappedSize = 0x4000000U, */
    .flags = CY_SMIF_FLAG_DETECT_SFDP,
    .slaveSelect = CY_SMIF_SLAVE_SELECT_0,
    .dataSelect = CY_SMIF_DATA_SEL0,
    .deviceCfg = &dev_sfdp_0
};

cy_stc_smif_mem_config_t *mems_sfdp[1] =
{
    &mem_sfdp_0
};

static cy_stc_smif_block_config_t smifBlockConfig_sfdp =
{
    .memCount = 1,
    .memConfig = mems_sfdp,
};

static cy_stc_smif_block_config_t *smif_blk_config;

static cy_stc_smif_context_t QSPI_context;

cy_stc_smif_config_t const QSPI_config =
{
    .mode = CY_SMIF_NORMAL,
    .deselectDelay = 1,
    .rxClockSel = CY_SMIF_SEL_INV_INTERNAL_CLK,
    .blockEvent = CY_SMIF_BUS_ERROR
};

cy_stc_sysint_t smifIntConfig =
{/* ATTENTION: make sure proper Interrupts configured for CM0p or M4 cores */
    .intrSrc = NvicMux7_IRQn,
    .cm0pSrc = smif_interrupt_IRQn,
    .intrPriority = 1
};

/* SMIF pinouts configurations */
static cy_stc_gpio_pin_config_t QSPI_SS_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG_IN_OFF,
	.hsiom = P11_2_SMIF_SPI_SELECT0, /* lets use SS0 by default */
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};
const cy_stc_gpio_pin_config_t QSPI_DATA3_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG,
	.hsiom = P11_3_SMIF_SPI_DATA3,
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};
const cy_stc_gpio_pin_config_t QSPI_DATA2_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG,
	.hsiom = P11_4_SMIF_SPI_DATA2,
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};
const cy_stc_gpio_pin_config_t QSPI_DATA1_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG,
	.hsiom = P11_5_SMIF_SPI_DATA1,
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};
const cy_stc_gpio_pin_config_t QSPI_DATA0_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG,
	.hsiom = P11_6_SMIF_SPI_DATA0,
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};
const cy_stc_gpio_pin_config_t QSPI_SCK_config =
{
	.outVal = 1,
	.driveMode = CY_GPIO_DM_STRONG_IN_OFF,
	.hsiom = P11_7_SMIF_SPI_CLK,
	.intEdge = CY_GPIO_INTR_DISABLE,
	.intMask = 0UL,
	.vtrip = CY_GPIO_VTRIP_CMOS,
	.slewRate = CY_GPIO_SLEW_FAST,
	.driveSel = CY_GPIO_DRIVE_1_2,
	.vregEn = 0UL,
	.ibufMode = 0UL,
	.vtripSel = 0UL,
	.vrefSel = 0UL,
	.vohSel = 0UL,
};

static bool qspi_is_semper_flash(void);
static cy_en_smif_status_t qspi_configure_semper_flash(void);
static cy_en_smif_status_t qspi_read_memory_id(uint8_t *id, uint16_t length);
static cy_en_smif_status_t qspi_read_register(uint32_t address, uint8_t *value);
static cy_en_smif_status_t qspi_write_register(uint32_t address, uint8_t value);
static cy_en_smif_status_t qspi_enter_4byte_addr_mode(void);
static void value_to_byte_array(uint32_t value, uint8_t *byteArray,
                                uint32_t startPos, uint32_t size);
static cy_en_smif_status_t poll_transfer_status(SMIF_Type const *base,
                                                cy_en_smif_txfr_status_t transferStatus,
                                                cy_stc_smif_context_t const *context);

void Isr_SMIF(void)
{
    Cy_SMIF_Interrupt(QSPIPort, &QSPI_context);
}

cy_en_smif_status_t qspi_init_hardware()
{
    cy_en_smif_status_t st;


    Cy_GPIO_Pin_Init(D3Port, D3Pin, &QSPI_DATA3_config);
    Cy_GPIO_SetHSIOM(D3Port, D3Pin, D3MuxPort);

    Cy_GPIO_Pin_Init(D2Port, D2Pin, &QSPI_DATA2_config);
    Cy_GPIO_SetHSIOM(D2Port, D2Pin, D2MuxPort);

    Cy_GPIO_Pin_Init(D1Port, D1Pin, &QSPI_DATA1_config);
    Cy_GPIO_SetHSIOM(D1Port, D1Pin, D1MuxPort);

    Cy_GPIO_Pin_Init(D0Port, D0Pin, &QSPI_DATA0_config);
    Cy_GPIO_SetHSIOM(D0Port, D0Pin, D0MuxPort);

	Cy_GPIO_Pin_Init(SCKPort, SCKPin, &QSPI_SCK_config);
    Cy_GPIO_SetHSIOM(SCKPort, SCKPin, SCKMuxPort);

    Cy_SysClk_ClkHfSetSource(CY_SYSCLK_CLKHF_IN_CLKPATH2, CY_SYSCLK_CLKHF_IN_CLKPATH0);
    Cy_SysClk_ClkHfSetDivider(CY_SYSCLK_CLKHF_IN_CLKPATH2, CY_SMIF_SYSCLK_HFCLK_DIVIDER);
    Cy_SysClk_ClkHfEnable(CY_SYSCLK_CLKHF_IN_CLKPATH2);

    /*
     * Setup the interrupt for the SMIF block.  For the CM0 there
     * is a two stage process to setup the interrupts.
     */
    Cy_SysInt_Init(&smifIntConfig, Isr_SMIF);

    st = Cy_SMIF_Init(QSPIPort, &QSPI_config, 1000, &QSPI_context);
    if (st != CY_SMIF_SUCCESS)
    {
        return st;
    }
    NVIC_EnableIRQ(smifIntConfig.intrSrc); /* Finally, Enable the SMIF interrupt */

    Cy_SMIF_Enable(QSPIPort, &QSPI_context);

    return CY_SMIF_SUCCESS;
}

cy_stc_smif_mem_config_t *qspi_get_memory_config(int index)
{
    return smif_blk_config->memConfig[index];
}

SMIF_Type *qspi_get_device()
{
    return QSPIPort;
}

cy_stc_smif_context_t *qspi_get_context()
{
    return &QSPI_context;
}

#define SEMPER_ID_LENGTH        (6U)

#define SEMPER_ID_MANUF         (0x34)
#define SEMPER_ID_DEV_MSB1      (0x2A)
#define SEMPER_ID_DEV_MSB2      (0x2B)
#define SEMPER_ID_DEV_LSB1      (0x19)
#define SEMPER_ID_DEV_LSB2      (0x1A)
#define SEMPER_ID_DEV_LSB3      (0x1B)
#define SEMPER_ID_LEN           (0x0F)
#define SEMPER_ID_SECTARCH      (0x03)
#define SEMPER_ID_FAMILY        (0x90)

#define SEMPER_WRARG_CMD        (0x71U) /* Write Any Register command */
#define SEMPER_RDARG_CMD        (0x65U) /* Read Any Register command */
#define SEMPER_EN4BA_CMD        (0xB7U) /* Enter 4 Byte Address Mode */
#define SEMPER_ER256_CMD        (0xD8U) /* Erase 256-KB Sector */

#define SEMPER_CFR2N_ADDR       (0x00000003UL) /* Non-volatile Configuration Register 2 address */
#define SEMPER_CFR3N_ADDR       (0x00000004UL) /* Non-volatile Configuration Register 3 address */

#define SEMPER_CFR2N_ADRBYT     (1U << 7U) /* Address Byte Length selection bit offset in CFR2N register */
#define SEMPER_CFR3N_UNHYSA     (1U << 3U) /* Uniform or Hybrid Sector Architecture selection bit offset in CFR3N register */

#define SEMPER_WRARG_DATA_INDEX (4U) /* Input data index for WRARG command */

#define SEMPER_WR_NV_TIMEOUT    (500000U) /* Nonvolatile Register Write operation timeout */

#define SEMPER_ADDR_LEN         (4U)

#define SEMPER_ERASE_SIZE       (262144u) /* Erase size for Semper Flash is 256KB */

#define PARAM_ID_MSB_OFFSET     (0x08U)  /* The offset of Parameter ID MSB */
#define PARAM_ID_LSB_MASK       (0xFFUL) /* The mask of Parameter ID LSB */

cy_en_smif_status_t qspi_init(cy_stc_smif_block_config_t *blk_config)
{
    cy_en_smif_status_t st;

    st = qspi_init_hardware();
    if (st == CY_SMIF_SUCCESS)
    {
        smif_blk_config = blk_config;
        st = Cy_SMIF_MemInit(QSPIPort, smif_blk_config, &QSPI_context);

        if(qspi_is_semper_flash() == true)
        {
            st = qspi_configure_semper_flash();
        }
    }
    return st;
}

static bool qspi_is_semper_flash(void)
{
    bool isSemper = false;
    cy_en_smif_status_t status;
    uint8_t buff[SEMPER_ID_LENGTH];

    status = qspi_read_memory_id(buff, SEMPER_ID_LENGTH);

    if(CY_SMIF_SUCCESS == status)
    {
        isSemper = true;

        /* Check Manufacturer and Device ID if it is Semper flash */
        if(buff[0] != SEMPER_ID_MANUF)
        {
            isSemper = false;
        }

        if(isSemper && ((buff[1u] != SEMPER_ID_DEV_MSB1) &&
                        (buff[1u] != SEMPER_ID_DEV_MSB2)))
        {
            isSemper = false;
        }

        if(isSemper && ((buff[2u] != SEMPER_ID_DEV_LSB1) &&
                        (buff[2u] != SEMPER_ID_DEV_LSB2) &&
                        (buff[2u] != SEMPER_ID_DEV_LSB3)))
        {
            isSemper = false;
        }

        if(isSemper && (buff[3u] != SEMPER_ID_LEN))
        {
            isSemper = false;
        }

        if(isSemper && (buff[4u] != SEMPER_ID_SECTARCH))
        {
            isSemper = false;
        }

        if(isSemper && (buff[5u] != SEMPER_ID_FAMILY))
        {
            isSemper = false;
        }
    }

    return isSemper;
}

static cy_en_smif_status_t qspi_configure_semper_flash(void)
{
    cy_en_smif_status_t status;
    uint8_t regVal;
    cy_stc_smif_mem_config_t *memCfg;

    status = qspi_enter_4byte_addr_mode();

    if(CY_SMIF_SUCCESS == status)
    {
        /* Set Address Byte Length selection to 4 bytes for instructions */
        status = qspi_read_register(SEMPER_CFR2N_ADDR, &regVal);
        if((CY_SMIF_SUCCESS == status) &&
           ((regVal & SEMPER_CFR2N_ADRBYT) == 0))
        {
            regVal |= SEMPER_CFR2N_ADRBYT;
            status = qspi_write_register(SEMPER_CFR2N_ADDR, regVal);
        }

        /* Enable Uniform Sector Architecture selection */
        status = qspi_read_register(SEMPER_CFR3N_ADDR, &regVal);
        if((CY_SMIF_SUCCESS == status) &&
           ((regVal & SEMPER_CFR3N_UNHYSA) == 0))
        {
            regVal |= SEMPER_CFR3N_UNHYSA;
            status = qspi_write_register(SEMPER_CFR3N_ADDR, regVal);
        }

        if(CY_SMIF_SUCCESS == status)
        {
            memCfg = qspi_get_memory_config(0u);
            memCfg->deviceCfg->eraseSize = SEMPER_ERASE_SIZE;
            memCfg->deviceCfg->eraseCmd->command = SEMPER_ER256_CMD;
        }
    }

    return status;
}

/* Read 6 bytes of Manufacturer and Device ID */
static cy_en_smif_status_t qspi_read_memory_id(uint8_t *id, uint16_t length)
{
    cy_en_smif_status_t status;
    cy_stc_smif_mem_config_t *memCfg;
    uint8_t command = 0x9Fu;
    uint16_t dummyCycles = 64u;

    memCfg = qspi_get_memory_config(0u);

    status = Cy_SMIF_TransmitCommand(QSPIPort,
                                    command,
                                    CY_SMIF_WIDTH_SINGLE,
                                    0u,
                                    0u,
                                    CY_SMIF_WIDTH_SINGLE,
                                    memCfg->slaveSelect,
                                    CY_SMIF_TX_NOT_LAST_BYTE,
                                    &QSPI_context);

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_SendDummyCycles(QSPIPort, dummyCycles);
    }

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_ReceiveData(QSPIPort, id, length,
                                    CY_SMIF_WIDTH_SINGLE,
                                    NULL, /* Callback function is not used */
                                    &QSPI_context);
    }

    /* Wait until the SMIF block completes receiving data */
    if(CY_SMIF_SUCCESS == status)
    {
        status = poll_transfer_status(QSPIPort, CY_SMIF_REC_CMPLT, &QSPI_context);
    }

    return status;
}

static cy_en_smif_status_t qspi_read_register(uint32_t address, uint8_t *value)
{
    cy_en_smif_status_t status;
    cy_stc_smif_mem_config_t *memCfg;
    uint8_t addressArray[SEMPER_ADDR_LEN];
    uint16_t dummyCycles = 8u;

    value_to_byte_array(address, addressArray, 0u, sizeof(addressArray));

    memCfg = qspi_get_memory_config(0u);

    status = Cy_SMIF_TransmitCommand(QSPIPort,
                                    SEMPER_RDARG_CMD,
                                    CY_SMIF_WIDTH_SINGLE,
                                    addressArray,
                                    sizeof(addressArray),
                                    CY_SMIF_WIDTH_SINGLE,
                                    memCfg->slaveSelect,
                                    CY_SMIF_TX_NOT_LAST_BYTE,
                                    &QSPI_context);

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_SendDummyCycles(QSPIPort, dummyCycles);
    }

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_ReceiveDataBlocking(QSPIPort, value,
                    CY_SMIF_READ_ONE_BYTE, CY_SMIF_WIDTH_SINGLE, &QSPI_context);
    }

    return status;
}

static cy_en_smif_status_t qspi_write_register(uint32_t address, uint8_t value)
{
    cy_en_smif_status_t status;
    cy_stc_smif_mem_config_t *memCfg;
    uint8_t data[SEMPER_ADDR_LEN + 1u];

    value_to_byte_array(address, data, 0u, SEMPER_ADDR_LEN);

    data[SEMPER_WRARG_DATA_INDEX] = value;

    memCfg = qspi_get_memory_config(0u);

    status = Cy_SMIF_MemCmdWriteEnable(QSPIPort, memCfg, &QSPI_context);

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_TransmitCommand(QSPIPort, SEMPER_WRARG_CMD,
                                        CY_SMIF_WIDTH_SINGLE,
                                        data, sizeof(data),
                                        CY_SMIF_WIDTH_SINGLE,
                                        memCfg->slaveSelect,
                                        CY_SMIF_TX_LAST_BYTE,
                                        &QSPI_context);
    }

    if(CY_SMIF_SUCCESS == status)
    {
        status = Cy_SMIF_MemIsReady(QSPIPort, memCfg, SEMPER_WR_NV_TIMEOUT,
                                    &QSPI_context);
    }

    return status;
}

static cy_en_smif_status_t qspi_enter_4byte_addr_mode(void)
{
    cy_en_smif_status_t status;
    cy_stc_smif_mem_config_t *memCfg;

    memCfg = qspi_get_memory_config(0u);

    status = Cy_SMIF_TransmitCommand(QSPIPort, SEMPER_EN4BA_CMD,
                                    CY_SMIF_WIDTH_SINGLE,
                                    CY_SMIF_CMD_WITHOUT_PARAM,
                                    CY_SMIF_CMD_WITHOUT_PARAM,
                                    CY_SMIF_WIDTH_SINGLE,
                                    memCfg->slaveSelect,
                                    CY_SMIF_TX_LAST_BYTE,
                                    &QSPI_context);

    return status;
}

static void value_to_byte_array(uint32_t value, uint8_t *byteArray, uint32_t startPos, uint32_t size)
{
    do
    {
        size--;
        byteArray[size + startPos] = (uint8_t)(value & PARAM_ID_LSB_MASK);
        value >>= PARAM_ID_MSB_OFFSET; /* Shift to get the next byte */
    } while (size > 0U);
}

static cy_en_smif_status_t poll_transfer_status(SMIF_Type const *base, cy_en_smif_txfr_status_t transferStatus,
                                              cy_stc_smif_context_t const *context)
{
    cy_en_smif_status_t status = CY_SMIF_SUCCESS;
    uint32_t transferTimeout = SMIF_TRANSFER_TIMEOUT;

    while (((uint32_t)transferStatus != Cy_SMIF_GetTransferStatus(base, context)) && (transferTimeout > 0UL))
    {
        Cy_SysLib_DelayUs(CY_SMIF_WAIT_1_UNIT);
        transferTimeout--;
    }

    if((uint32_t)transferStatus != Cy_SMIF_GetTransferStatus(base, context))
    {
        status = CY_SMIF_EXCEED_TIMEOUT;
    }

    return status;
}

cy_en_smif_status_t qspi_init_sfdp(uint32_t smif_id)
{
    cy_en_smif_status_t stat = CY_SMIF_SUCCESS;

    cy_stc_smif_mem_config_t **memCfg = smifBlockConfig_sfdp.memConfig;

    GPIO_PRT_Type *SS_Port;
    int SS_Pin;
    en_hsiom_sel_t SS_MuxPort;

    switch(smif_id)
    {
    case 1:
        (*memCfg)->slaveSelect = CY_SMIF_SLAVE_SELECT_0;
        break;
    case 2:
        (*memCfg)->slaveSelect = CY_SMIF_SLAVE_SELECT_1;
        break;
    case 3:
        (*memCfg)->slaveSelect = CY_SMIF_SLAVE_SELECT_2;
        break;
#if(CY_BOOTLOADER_SMIF_SS_CFG_NUM > 3)
    case 4:
        (*memCfg)->slaveSelect = CY_SMIF_SLAVE_SELECT_3;
        break;
#endif
    default:
        stat = -1;
        break;
    }

    if(CY_SMIF_SUCCESS == stat)
    {
        SS_Port = qspi_SS_Configuration[smif_id-1].SS_Port;
        SS_Pin = qspi_SS_Configuration[smif_id-1].SS_Pin;
        SS_MuxPort = qspi_SS_Configuration[smif_id-1].SS_Mux;

        QSPI_SS_config.hsiom = SS_MuxPort;

        Cy_GPIO_Pin_Init(SS_Port, SS_Pin, &QSPI_SS_config);
        Cy_GPIO_SetHSIOM(SS_Port, SS_Pin, SS_MuxPort);

        stat = qspi_init(&smifBlockConfig_sfdp);
    }
    return stat;
}

uint32_t qspi_get_prog_size(void)
{
    cy_stc_smif_mem_config_t **memCfg = smifBlockConfig_sfdp.memConfig;
    return (*memCfg)->deviceCfg->programSize;
}

uint32_t qspi_get_erase_size(void)
{
    cy_stc_smif_mem_config_t **memCfg = smifBlockConfig_sfdp.memConfig;
    return (*memCfg)->deviceCfg->eraseSize;
}

uint32_t qspi_get_mem_size(void)
{
    cy_stc_smif_mem_config_t **memCfg = smifBlockConfig_sfdp.memConfig;
    return (*memCfg)->deviceCfg->memSize;
}

