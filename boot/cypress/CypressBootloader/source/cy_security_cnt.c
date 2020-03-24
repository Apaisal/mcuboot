/*
 * Copyright (c) 2020 Arm Limited.
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
 */

#include "bootutil/security_cnt.h"
#include "bootutil/bootutil_log.h"
#include <stdint.h>

#include "cy_image_utils.h"

#include "cy_ipc_drv.h"

/** Flashboot Counters SysCall opcode */
#define FB_COUNTERS_SYSCALL_OPCODE          (0x36UL << 24UL)

/** Flashboot SysCall return codes */
#define CY_FB_SYSCALL_SUCCESS               (0xA0000000UL)

/** Timeout values */
#define PSACRYPTO_SYSCALL_TIMEOUT_SHORT     (15000UL)
#define PSACRYPTO_SYSCALL_TIMEOUT_LONG      (2000000000UL)

/**
 *
 */
int32_t Cy_FbSysCall_Run(uint32_t *syscallCmd)
{
    int32_t status = 0;
    uint32_t timeout = 0U;

    /* Get IPC base register address */
    IPC_STRUCT_Type * ipcStruct = Cy_IPC_Drv_GetIpcBaseAddress(CY_IPC_CHAN_SYSCALL);

    while((CY_IPC_DRV_SUCCESS != Cy_IPC_Drv_LockAcquire(ipcStruct)) &&
            (timeout < PSACRYPTO_SYSCALL_TIMEOUT_SHORT))
    {
        ++timeout;
    }

    if(timeout < PSACRYPTO_SYSCALL_TIMEOUT_SHORT)
    {
        timeout = 0U;

        Cy_IPC_Drv_WriteDataValue(ipcStruct, (uint32_t)syscallCmd);
        Cy_IPC_Drv_AcquireNotify(ipcStruct, (1<<CY_IPC_CHAN_SYSCALL));

        while((Cy_IPC_Drv_IsLockAcquired(ipcStruct)) &&
                (timeout < PSACRYPTO_SYSCALL_TIMEOUT_LONG))
        {
            ++timeout;
        }

        if(timeout < PSACRYPTO_SYSCALL_TIMEOUT_LONG)
        {
            if(CY_FB_SYSCALL_SUCCESS != syscallCmd[0])
            {
                status = syscallCmd[0];
            }
        }
        else
        {
            status = -1;
        }
    }
    else
    {
        status = -1;
    }

    return status;
}


int32_t
boot_nv_security_counter_init(void)
{
    BOOT_LOG_DBG("> Init security counter");

    /* Do nothing. */
    BOOT_LOG_DBG(" * ok");

    return 0;
}

int32_t
boot_nv_security_counter_get(uint32_t image_id, uint32_t *security_cnt)
{
    int32_t status;
    uint8_t sec_cnt_id;

    BOOT_LOG_DBG("> Get security counter value, image ID = %d", (int)image_id);

    sec_cnt_id = cy_bootutil_get_image_sec_counter(image_id);

    uint32_t syscall_param[1];
    uint32_t syscall_cmd[2];

    syscall_cmd[0] = FB_COUNTERS_SYSCALL_OPCODE + (sec_cnt_id << 16);
    syscall_cmd[1] = (uint32_t)&syscall_param;

    status = Cy_FbSysCall_Run(syscall_cmd);

    if (status == 0)
    {
        *security_cnt = syscall_param[0];
    }

    BOOT_LOG_DBG(" * security counter: status = %d, id = %d, value = %d", (int)status, (int)sec_cnt_id, (int)*security_cnt);

    return status;
}

int32_t
boot_nv_security_counter_update(uint32_t image_id, uint32_t img_security_cnt)
{
    int32_t status;
    uint8_t sec_cnt_id;

    sec_cnt_id = cy_bootutil_get_image_sec_counter(image_id);

    BOOT_LOG_DBG("> Update security counter value, image ID = %d, cnt_id = %d, img_security_cnt = %d", (int)image_id, (int)sec_cnt_id, (int)img_security_cnt);

    uint32_t syscall_param[1];
    uint32_t syscall_cmd[2];

    syscall_cmd[0] = FB_COUNTERS_SYSCALL_OPCODE + (sec_cnt_id << 16) + (1 << 8);
    syscall_cmd[1] = (uint32_t)&syscall_param;

    syscall_param[0] = img_security_cnt;

    status = Cy_FbSysCall_Run(syscall_cmd);

    if (status == 0)
    {
        BOOT_LOG_DBG(" * update ok");
    }
    else
    {
        BOOT_LOG_DBG(" * update ERROR");
    }

    return status;
}
