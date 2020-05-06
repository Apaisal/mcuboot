/***************************************************************************//**
* \file cy_bootloader_services.c
* \version 1.0
*
* \brief
*  This is the source code file for implementation of bootloader services.
*
********************************************************************************
* \copyright
* Copyright 2019, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/
#include <string.h>

#include "system_psoc6.h"
#include "cy_ipc_sema.h"
#include "cy_ipc_pipe.h"
#include "cy_ipc_drv.h"
#include "cy_scb_uart.h"
#include "cy_syspm.h"

#include "bootutil/bootutil_log.h"

#include "cy_bootloader_services.h"
#include "cy_bootloader_hw.h"
#include "cy_jwt_policy.h"
#include "cy_secure_utils.h"
#include "cyprotection.h"

#ifdef MCUBOOT_HAVE_ASSERT_H
#include "mcuboot_config/mcuboot_assert.h"
#else
#define ASSERT assert
#endif

#define TST_MODE_TEST_MODE_MASK         (0x80000000UL)
#define CY_SRSS_TST_MODE_ADDR           (SRSS_BASE | 0x0100UL)

extern bnu_policy_t   cy_bl_bnu_policy;
extern debug_policy_t debug_policy;

extern const volatile uint32_t __sdata_start__[];
extern const volatile uint32_t __sdata_end__[];

extern const volatile uint32_t __bss_start__[];
extern const volatile uint32_t __bss_end__[];

extern const volatile uint32_t __HeapBase[];
extern const volatile uint32_t __HeapLimit[];

extern const volatile uint32_t __StackLimit[];
extern const volatile uint32_t __StackTop[];

extern void __set_MSP(uint32_t topOfMainStack);
extern void __disable_irq(void);

#if defined(CY_IPC_DEFAULT_CFG_DISABLE)
void Cy_SysIpcPipeIsrCm0(void)
{
    Cy_IPC_Pipe_ExecuteCallback(CY_IPC_EP_CYPIPE_CM0_ADDR);
}

static cy_en_ipcsema_status_t Cy_IPC_SemaInitLocal(uint32_t ipcChannel,
                                        uint32_t count, uint32_t memPtr[])
{
    /* Structure containing semaphores control data */
    __attribute__((section(".cy_pub_ram"))) static cy_stc_ipc_sema_t cy_semaData;

    cy_en_ipcsema_status_t retStatus = CY_IPC_SEMA_BAD_PARAM;

    /* Check for non Null pointers and count value */
    if ((NULL != memPtr) && (0u != count))
    {
        cy_semaData.maxSema  = count;
        cy_semaData.arrayPtr = memPtr;

        retStatus = Cy_IPC_Sema_InitExt(ipcChannel, &cy_semaData);
    }

    else
    {
        retStatus = CY_IPC_SEMA_BAD_PARAM;
    }

    return(retStatus);
}

/*
 * This function replaces part of standard SystemInit function if
 * CY_IPC_DEFAULT_CFG_DISABLE symbol is defined.
 * For correct work it requires zero initialization of the cy_pub_ram section.
 */
void Cy_BLServ_FlashInit(void)
{
    /* Allocate and initialize semaphores for the system operations. */
    __attribute__((section(".cy_pub_ram")))
    static uint32_t ipcSemaArray[CY_IPC_SEMA_COUNT / CY_IPC_SEMA_PER_WORD];

    (void) Cy_IPC_SemaInitLocal(CY_IPC_CHAN_SEMA, CY_IPC_SEMA_COUNT, ipcSemaArray);

    /* Create an array of endpoint structures */
    __attribute__((section(".cy_pub_ram")))
    static cy_stc_ipc_pipe_ep_t systemIpcPipeEpArray[CY_IPC_MAX_ENDPOINTS];

    Cy_IPC_Pipe_Config(systemIpcPipeEpArray);

    __attribute__((section(".cy_pub_ram")))
    static cy_ipc_pipe_callback_ptr_t systemIpcPipeSysCbArray[CY_SYS_CYPIPE_CLIENT_CNT];

    static const cy_stc_ipc_pipe_config_t systemIpcPipeConfigCm0 =
    {
    /* .ep0ConfigData */
        {
            /* .ipcNotifierNumber    */  CY_IPC_INTR_CYPIPE_EP0,
            /* .ipcNotifierPriority  */  CY_SYS_INTR_CYPIPE_PRIOR_EP0,
            /* .ipcNotifierMuxNumber */  CY_SYS_INTR_CYPIPE_MUX_EP0,
            /* .epAddress            */  CY_IPC_EP_CYPIPE_CM0_ADDR,
            /* .epConfig             */  CY_SYS_CYPIPE_CONFIG_EP0
        },
    /* .ep1ConfigData */
        {
            /* .ipcNotifierNumber    */  CY_IPC_INTR_CYPIPE_EP1,
            /* .ipcNotifierPriority  */  CY_SYS_INTR_CYPIPE_PRIOR_EP1,
            /* .ipcNotifierMuxNumber */  0u,
            /* .epAddress            */  CY_IPC_EP_CYPIPE_CM4_ADDR,
            /* .epConfig             */  CY_SYS_CYPIPE_CONFIG_EP1
        },
    /* .endpointClientsCount     */  CY_SYS_CYPIPE_CLIENT_CNT,
    /* .endpointsCallbacksArray  */  systemIpcPipeSysCbArray,
    /* .userPipeIsrHandler       */  &Cy_SysIpcPipeIsrCm0
    };

    if (cy_device->flashPipeRequired != 0u)
    {
        Cy_IPC_Pipe_Init(&systemIpcPipeConfigCm0);
    }

    __attribute__((section(".cy_pub_ram")))
    CY_ALIGN(4) static cy_stc_flash_notify_t ipcWaitMessageStc;
    Cy_Flash_InitExt(&ipcWaitMessageStc);
}
#endif  /* defined (CY_IPC_DEFAULT_CFG_DISABLE) */

CY_SECTION(".cy_ramfunc") CY_NOINLINE
// PSVP: static void Cy_BLServ_SRAMBusyLoop(void)
void Cy_BLServ_SRAMBusyLoop(void)
{
    while(1)
    {
#if defined(CY_BOOTLOADER_DIAGNOSTIC_GPIO)
        Cy_GPIO_Inv(LED_RED_PORT, LED_RED_PIN); /* toggle the pin */
        Cy_SysLib_DelayCycles(100000000/1);
#endif /* CY_BOOTLOADER_DIAGNOSTIC_GPIO */
    }
}

void Cy_BLServ_Assert(int expr)
{
    int rc = -1;

    if(0 == expr)
    {
        volatile perm_policy_t cm4ApPermission = debug_policy.m4_policy.permission;
        volatile perm_policy_t sysApPermission = debug_policy.sys_policy.permission;
        volatile uint32_t windowTime = cy_bl_bnu_policy.bnu_img_policy[0].acq_win;

        BOOT_LOG_ERR("There is an error occurred during bootloader flow. MCU stopped.");

        /* Clean SRAM */
        memset((void*)__sdata_start__, 0, ((size_t)__sdata_end__ - (size_t)__sdata_start__));

        memset((void*)__bss_start__, 0, ((size_t)__bss_end__ - (size_t)__bss_start__));
        memset((void*)__HeapBase,    0, ((size_t)__HeapLimit - (size_t)__HeapBase));

        debug_policy.m4_policy.permission = cm4ApPermission;
        debug_policy.sys_policy.permission = sysApPermission;
        cy_bl_bnu_policy.bnu_img_policy[0].acq_win = windowTime;

        __set_MSP((uint32_t)__HeapBase);
        memset((void*)__StackLimit,  0, ((size_t)__StackTop - (size_t)__StackLimit));

        __set_MSP((uint32_t)__StackTop);

        release_protections(true);

        /* System initialization after .bss section was cleared */
        Cy_BLServ_SystemInit();

        rc = Cy_Utils_EnableAccessPorts(windowTime);
        if(0 != rc)
        {
            BOOT_LOG_ERR("Error %x while enabling access ports", rc);
        }

        if((CY_GET_REG32(CY_SRSS_TST_MODE_ADDR) & TST_MODE_TEST_MODE_MASK) != 0UL)
        {
            Cy_Utils_AcquireWindow();

            __disable_irq();
        }

        Cy_SysEnableCM4(CY_BL_CM4_ROM_LOOP_ADDR);

        Cy_BLServ_SRAMBusyLoop();
    }
}

#if 0 /* need to test this */
int Cy_BLServ_FreeHeap(void)
{
   cy_en_prot_status_t status = CY_PROT_SUCCESS;
   uint8_t *heapStart = (uint8_t*)&__HeapBase;
   uint8_t *heapEnd = (uint8_t*)&__HeapLimit;

   memset(heapStart, 0, (heapEnd - heapStart));

   status = release_protections();

   return (int)status;
}
#endif

#if defined(__NO_SYSTEM_INIT)
void Cy_BLServ_SystemInit(void)
{
    Cy_PDL_Init(CY_DEVICE_CFG);

    SystemCoreClockUpdate();

#if !defined(CY_IPC_DEFAULT_CFG_DISABLE)
    /* Allocate and initialize semaphores for the system operations. */
    CY_SECTION(".cy_sharedmem")
    static uint32_t ipcSemaArray[CY_IPC_SEMA_COUNT / CY_IPC_SEMA_PER_WORD];

    (void) Cy_IPC_Sema_Init(CY_IPC_CHAN_SEMA, CY_IPC_SEMA_COUNT, ipcSemaArray);


    /********************************************************************************
    *
    * Initializes the system pipes. The system pipes are used by BLE and Flash.
    *
    * If the default startup file is not used, or SystemInit() is not called in your
    * project, call the following three functions prior to executing any flash or
    * EmEEPROM write or erase operation:
    *  -# Cy_IPC_Sema_Init()
    *  -# Cy_IPC_Pipe_Config()
    *  -# Cy_IPC_Pipe_Init()
    *  -# Cy_Flash_Init()
    *
    *******************************************************************************/

    /* Create an array of endpoint structures */
    static cy_stc_ipc_pipe_ep_t systemIpcPipeEpArray[CY_IPC_MAX_ENDPOINTS];

    Cy_IPC_Pipe_Config(systemIpcPipeEpArray);

    static cy_ipc_pipe_callback_ptr_t systemIpcPipeSysCbArray[CY_SYS_CYPIPE_CLIENT_CNT];

    static const cy_stc_ipc_pipe_config_t systemIpcPipeConfigCm0 =
    {
    /* .ep0ConfigData */
        {
            /* .ipcNotifierNumber    */  CY_IPC_INTR_CYPIPE_EP0,
            /* .ipcNotifierPriority  */  CY_SYS_INTR_CYPIPE_PRIOR_EP0,
            /* .ipcNotifierMuxNumber */  CY_SYS_INTR_CYPIPE_MUX_EP0,
            /* .epAddress            */  CY_IPC_EP_CYPIPE_CM0_ADDR,
            /* .epConfig             */  CY_SYS_CYPIPE_CONFIG_EP0
        },
    /* .ep1ConfigData */
        {
            /* .ipcNotifierNumber    */  CY_IPC_INTR_CYPIPE_EP1,
            /* .ipcNotifierPriority  */  CY_SYS_INTR_CYPIPE_PRIOR_EP1,
            /* .ipcNotifierMuxNumber */  0u,
            /* .epAddress            */  CY_IPC_EP_CYPIPE_CM4_ADDR,
            /* .epConfig             */  CY_SYS_CYPIPE_CONFIG_EP1
        },
    /* .endpointClientsCount     */  CY_SYS_CYPIPE_CLIENT_CNT,
    /* .endpointsCallbacksArray  */  systemIpcPipeSysCbArray,
    /* .userPipeIsrHandler       */  &Cy_SysIpcPipeIsrCm0
    };

    if (cy_device->flashPipeRequired != 0u)
    {
        Cy_IPC_Pipe_Init(&systemIpcPipeConfigCm0);
    }

#if defined(CY_DEVICE_PSOC6ABLE2)
    Cy_Flash_Init();
#endif /* defined(CY_DEVICE_PSOC6ABLE2) */

#endif /* !defined(CY_IPC_DEFAULT_CFG_DISABLE) */
}
#endif /* __NO_SYSTEM_INIT */
