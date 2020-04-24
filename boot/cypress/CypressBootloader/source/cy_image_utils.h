/***************************************************************************//**
* \file cy_image_utils.h
* \version 1.0
*
* \brief
*  This is the header file for implementation of bootloader image policy
*  utility functions.
*
********************************************************************************
* \copyright
* Copyright 2020, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#ifndef SOURCE_CY_IMAGE_UTILS_H_
#define SOURCE_CY_IMAGE_UTILS_H_

#include "flash_map_backend/flash_map_backend.h"

int cy_bootutil_get_multi_idx(const struct flash_area *fap);

int cy_bootutil_get_slot_id(const struct flash_area *fap);

int cy_bootutil_check_image_id(const struct flash_area *fap, uint8_t image_id);

int cy_bootutil_check_upgrade(const struct flash_area *fap);

int cy_bootutil_get_image_sign_key(const struct flash_area *fap);

int cy_bootutil_get_image_enc_key(const struct flash_area *fap);

int cy_bootutil_find_image_sec_counter(const struct flash_area *fap);

int cy_bootutil_get_image_sec_counter(uint32_t image_id);

int cy_bootutil_get_image_encrypt(const struct flash_area *fap);

#endif /* SOURCE_CY_IMAGE_UTILS_H_ */
