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
#include "cy_secure_utils.h"

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
    int32_t status = -1;
    int sec_cnt_id;

    BOOT_LOG_DBG("> Get security counter value, image ID = %d", (int)image_id);

    sec_cnt_id = cy_bootutil_get_image_sec_counter(image_id);

    if (sec_cnt_id >= 0)
    {
        status = Cy_Utils_GetSecCounter((uint32_t)sec_cnt_id, security_cnt);
    }

    BOOT_LOG_DBG(" * security counter: status = %d, id = %d, value = %d", (int)status, (int)sec_cnt_id, (int)*security_cnt);

    return status;
}

int32_t
boot_nv_security_counter_update(uint32_t image_id, uint32_t img_security_cnt)
{
    int32_t status = -1;
    int sec_cnt_id;

    sec_cnt_id = cy_bootutil_get_image_sec_counter(image_id);

    if (sec_cnt_id >= 0)
    {
        BOOT_LOG_DBG("> Update security counter value, image ID = %d, cnt_id = %d, img_security_cnt = %d", (int)image_id, (int)sec_cnt_id, (int)img_security_cnt);

        status = Cy_Utils_UpdateSecCounter((uint32_t)sec_cnt_id, img_security_cnt);
    }

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
