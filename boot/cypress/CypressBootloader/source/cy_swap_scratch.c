/***************************************************************************//**
* \file cy_swap_scratch.c
* \version 1.0
*
* \brief
*  This is the source file for implementation of bootloader scratch
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

#include "bootutil_priv.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"

#include "sysflash/sysflash.h"
#include <stdint.h>

#include "cy_jwt_policy.h"

extern bnu_policy_t cy_bl_bnu_policy;

#if !defined(MCUBOOT_SWAP_USING_MOVE)

int
boot_read_image_header(struct boot_loader_state *state, int slot,
                       struct image_header *out_hdr, struct boot_status *bs)
{
    const struct flash_area *fap;
    int area_id;
    int rc;

    (void)bs;

// TODO: run-time multi-image
// #if (BOOT_IMAGE_NUMBER == 1)
    (void)state;
// #endif

    area_id = flash_area_id_from_multi_image_slot((int)BOOT_CURR_IMG(state), slot);

    rc = flash_area_open((uint8_t)area_id, &fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    /* Check for upgrade is enabled in the policy */
    rc = cy_bootutil_check_upgrade(fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    rc = flash_area_read(fap, 0, (uint8_t*)out_hdr, sizeof(*out_hdr));
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    rc = 0;

done:
    flash_area_close(fap);
    return rc;
}

/*
 * Slots are compatible when all sectors that store up to to size of the image
 * round up to sector size, in both slot's are able to fit in the scratch
 * area, and have sizes that are a multiple of each other (powers of two
 * presumably!).
 */
int
boot_slots_compatible(struct boot_loader_state *state)
{
    size_t num_sectors_primary;
    size_t num_sectors_secondary;
    size_t sz0, sz1;
    size_t primary_slot_sz, secondary_slot_sz;
#ifndef MCUBOOT_OVERWRITE_ONLY
    size_t scratch_sz;
#endif
    size_t i, j;
    int8_t smaller;

    /* Check for upgrade is enabled in the policy */
    if (cy_bootutil_check_upgrade(BOOT_IMG_AREA(state, BOOT_SECONDARY_SLOT)) != 0) {
        BOOT_LOG_WRN("Cannot upgrade: upgrade is disabled");
        return 0;
    }

    num_sectors_primary = boot_img_num_sectors(state, BOOT_PRIMARY_SLOT);
    num_sectors_secondary = boot_img_num_sectors(state, BOOT_SECONDARY_SLOT);
    if ((num_sectors_primary > (size_t)BOOT_MAX_IMG_SECTORS) ||
        (num_sectors_secondary > (size_t)BOOT_MAX_IMG_SECTORS)) {
        BOOT_LOG_WRN("Cannot upgrade: more sectors than allowed");
        return 0;
    }

#ifndef MCUBOOT_OVERWRITE_ONLY
    scratch_sz = boot_scratch_area_size(state);
#endif

    /*
     * The following loop scans all sectors in a linear fashion, assuring that
     * for each possible sector in each slot, it is able to fit in the other
     * slot's sector or sectors. Slot's should be compatible as long as any
     * number of a slot's sectors are able to fit into another, which only
     * excludes cases where sector sizes are not a multiple of each other.
     */
    i = sz0 = primary_slot_sz = 0;
    j = sz1 = secondary_slot_sz = 0;
    smaller = 0;
    while (i < num_sectors_primary || j < num_sectors_secondary) {
        if (sz0 == sz1) {
            sz0 += boot_img_sector_size(state, BOOT_PRIMARY_SLOT, i);
            sz1 += boot_img_sector_size(state, BOOT_SECONDARY_SLOT, j);
            i++;
            j++;
        } else if (sz0 < sz1) {
            sz0 += boot_img_sector_size(state, BOOT_PRIMARY_SLOT, i);
            /* Guarantee that multiple sectors of the secondary slot
             * fit into the primary slot.
             */
            if (smaller == 2) {
                BOOT_LOG_WRN("Cannot upgrade: slots have non-compatible sectors");
                return 0;
            }
            smaller = 1;
            i++;
        } else {
            sz1 += boot_img_sector_size(state, BOOT_SECONDARY_SLOT, j);
            /* Guarantee that multiple sectors of the primary slot
             * fit into the secondary slot.
             */
            if (smaller == 1) {
                BOOT_LOG_WRN("Cannot upgrade: slots have non-compatible sectors");
                return 0;
            }
            smaller = 2;
            j++;
        }
#ifndef MCUBOOT_OVERWRITE_ONLY
        if (sz0 == sz1) {
            primary_slot_sz += sz0;
            secondary_slot_sz += sz1;
            /* Scratch has to fit each swap operation to the size of the larger
             * sector among the primary slot and the secondary slot.
             */
            if (sz0 > scratch_sz || sz1 > scratch_sz) {
                BOOT_LOG_WRN("Cannot upgrade: not all sectors fit inside scratch");
                return 0;
            }
            smaller = sz0 = sz1 = 0;
        }
#endif
    }

    if ((i != num_sectors_primary) ||
        (j != num_sectors_secondary)
#ifndef MCUBOOT_OVERWRITE_ONLY
        || (primary_slot_sz != secondary_slot_sz)
#endif
       ) {
        BOOT_LOG_WRN("Cannot upgrade: slots are not compatible");
        return 0;
    }

    return 1;
}

#endif
