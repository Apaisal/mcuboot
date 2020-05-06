/***************************************************************************//**
* \file cy_image_utils.c
* \version 1.0
*
* \brief
*  This is the source file for implementation of bootloader image policy
*  utility functions.
*
********************************************************************************
* \copyright
* Copyright 2020, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include "cy_image_utils.h"

#include "bootutil/bootutil_log.h"

#include "sysflash/sysflash.h"
#include <stdint.h>

#include "cy_jwt_policy.h"

extern bnu_policy_t cy_bl_bnu_policy;

int cy_bootutil_get_multi_idx(const struct flash_area *fap)
{
    int multi_idx = -1;

    /* find out if it is some of multi-image */
    if((fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(0)) ||
        (fap->fa_id == FLASH_AREA_IMAGE_SECONDARY(0)))
    {
        multi_idx = 0;
    }
    else
    if((fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(1)) ||
        (fap->fa_id == FLASH_AREA_IMAGE_SECONDARY(1)))
    {
        multi_idx = 1;
    }

    return multi_idx;
}

int cy_bootutil_get_slot_id(const struct flash_area *fap)
{
    int slot_id = -1;

    /* find out if it is slot_0 or slot_1*/
    if((fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(0)) ||
        (fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(1)))
    {
        slot_id = 0;
    }
    else
    if((fap->fa_id == FLASH_AREA_IMAGE_SECONDARY(0)) ||
        (fap->fa_id == FLASH_AREA_IMAGE_SECONDARY(1)))
    {
        slot_id = 1;
    }

    return slot_id;
}

int cy_bootutil_check_image_id(const struct flash_area *fap, uint8_t image_id)
{
    int rc = -1;
    int img_idx = -1;

    img_idx = cy_bootutil_get_multi_idx(fap);

    if ((img_idx >= 0) && (img_idx < POLICY_MAX_N_OF_MULTI_IMGAGE))
    {
        rc = (int)(image_id != cy_bl_bnu_policy.bnu_img_policy[img_idx].id);
    }

    return rc;
}

int cy_bootutil_check_upgrade(const struct flash_area *fap)
{
    int rc = -1;
    int img_idx = -1, slot_id = -1;

    slot_id = cy_bootutil_get_slot_id(fap);

    if (slot_id >= 0)
    {
        if (slot_id > 0)
        {
            /* This is an UPGRADE slot */
            img_idx = cy_bootutil_get_multi_idx(fap);

            if (img_idx >= 0)
            {
                rc = (int)(!cy_bl_bnu_policy.bnu_img_policy[img_idx].upgrade);
            }
        }
        else
        {
            /* This is a BOOT slot, no upgrade policy checking */
            rc = 0;
        }
    }

    return rc;
}

int cy_bootutil_get_image_sign_key(const struct flash_area *fap)
{
    int key = 0;
    int multi_idx = -1;

    /* find out if it is some of multi-image */
    multi_idx = cy_bootutil_get_multi_idx(fap);

    if ((multi_idx >= 0) && (multi_idx < POLICY_MAX_N_OF_MULTI_IMGAGE))
    {
        key = (int)cy_bl_bnu_policy.bnu_img_policy[multi_idx].boot_auth[0];
    }

    return key;
}

int cy_bootutil_get_image_enc_key(const struct flash_area *fap)
{
    int key = 0;
    int multi_idx = -1;

    /* find out if it is some of multi-image */
    multi_idx = cy_bootutil_get_multi_idx(fap);

    if ((multi_idx >= 0) && (multi_idx < POLICY_MAX_N_OF_MULTI_IMGAGE))
    {
        key = (int)cy_bl_bnu_policy.bnu_img_policy[multi_idx].encrypt_key_id;
    }

    return key;
}

int cy_bootutil_find_image_sec_counter(const struct flash_area *fap)
{
    int sec_cnt_id = -1;
    int multi_idx = -1;

    /* find out if it is some of multi-image */
    multi_idx = cy_bootutil_get_multi_idx(fap);

    if ((multi_idx >= 0) && (multi_idx < POLICY_MAX_N_OF_MULTI_IMGAGE))
    {

        sec_cnt_id = (int)cy_bl_bnu_policy.bnu_img_policy[multi_idx].monotonic;
    }

    return sec_cnt_id;
}

int cy_bootutil_get_image_sec_counter(uint32_t image_id)
{
    int sec_cnt_id = -1;

    if (image_id < (uint32_t)POLICY_MAX_N_OF_MULTI_IMGAGE)
    {

        sec_cnt_id = (int)cy_bl_bnu_policy.bnu_img_policy[image_id].monotonic;
    }

    return sec_cnt_id;
}

int cy_bootutil_get_image_encrypt(const struct flash_area *fap)
{
    int encrypt_value = -1;
    int multi_idx = -1;

    /* find out if it is some of multi-image */
    multi_idx = cy_bootutil_get_multi_idx(fap);

    if ((multi_idx >= 0) && (multi_idx < POLICY_MAX_N_OF_MULTI_IMGAGE))
    {
        encrypt_value = (int)cy_bl_bnu_policy.bnu_img_policy[multi_idx].encrypt;
    }

    return encrypt_value;
}

