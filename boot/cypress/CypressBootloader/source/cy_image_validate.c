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
* \copyright
*
* (c) 2018-2020, Cypress Semiconductor Corporation
* or a subsidiary of Cypress Semiconductor Corporation. All rights
* reserved.
*
* This software is a port of the open source MCUBoot project.
* This file was modified to fit Cypress Secure Bootloader design.
*
* Portions of this software, including source code, documentation and related
* materials ("Software"), are owned by Cypress Semiconductor
* Corporation or one of its subsidiaries ("Cypress") and is protected by
* and subject to worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-
* exclusive, non-transferable license to copy, modify, and compile the
* Software source code solely for use in connection with Cypress's
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
********************************************************************************/

#ifdef MCUBOOT_HAVE_ASSERT_H
#include "mcuboot_config/mcuboot_assert.h"
#else
#include <assert.h>
#endif

#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include <flash_map_backend/flash_map_backend.h>

#include "bootutil/image.h"
#include "bootutil/sha256.h"
#include "bootutil/sign_key.h"

#include "mcuboot_config/mcuboot_config.h"

#include "bootutil/bootutil_log.h"
#include "bootutil/security_cnt.h"

#ifdef MCUBOOT_ENC_IMAGES
#include "bootutil/enc_key.h"
#endif
#if defined(MCUBOOT_SIGN_RSA)
#include "mbedtls/rsa.h"
#endif
#if defined(MCUBOOT_SIGN_EC) || defined(MCUBOOT_SIGN_EC256)
#include "mbedtls/ecdsa.h"
#endif
#include "mbedtls/asn1.h"

#include "bootutil_priv.h"

#include "cy_image_utils.h"

/* Additional TLV tags */
#define IMAGE_TLV_CYSB_IMAGE_ID            0x81   /* Image ID */

#define IMAGE_CY_SEC_CNT_MAX_VALUE        255UL

/*
 * Compute SHA256 over the image.
 */
static int
bootutil_rawimg_hash(struct enc_key_data *enc_state, int image_index,
                  struct image_header *hdr, const struct flash_area *fap,
                  uint8_t *hash_result, uint8_t *seed, int seed_len)
{
    bootutil_sha256_context sha256_ctx = { 0x0 };
    uint32_t size;

    BOOT_LOG_DBG("> bootutil_rawimg_hash") ;

    // TODO: run-time multi-image
//#if (BOOT_IMAGE_NUMBER == 1) || !defined(MCUBOOT_ENC_IMAGES)
    (void)enc_state;
    (void)image_index;
//#endif

    psa_status_t psa_ret;

    psa_ret = bootutil_sha256_init(&sha256_ctx);

    if (0 == psa_ret)
    {
        /* in some cases (split image) the hash is seeded with data from
         * the loader image */
        if (seed && (seed_len > 0)) {
            psa_ret = bootutil_sha256_update(&sha256_ctx, seed, seed_len);
        }

        if (0 == psa_ret)
        {

            /* Hash is computed over image header and image itself. */
            size =  hdr->ih_hdr_size;
            size += hdr->ih_img_size;

            /* If protected TLVs are present they are also hashed. */
            size += hdr->ih_protect_tlv_size;

            psa_ret = bootutil_sha256_update(&sha256_ctx, (const void*)fap->fa_off, size);

        }

        if (0 == psa_ret)
        {
            psa_ret = bootutil_sha256_finish(&sha256_ctx, hash_result);
        }
    }

    BOOT_LOG_DBG("< bootutil_rawimg_hash") ;

    return (int)psa_ret;
}

/*
 * Compute SHA256 over the image.
 */
static int
bootutil_img_hash(struct enc_key_data *enc_state, int image_index,
                  struct image_header *hdr, const struct flash_area *fap,
                  uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *hash_result,
                  uint8_t *seed, int seed_len)
{
    bootutil_sha256_context sha256_ctx = { 0x0 };
    uint32_t blk_sz;
    uint32_t size;
    uint16_t hdr_size;
    uint32_t off;
    int rc;
    uint32_t blk_off;
    uint32_t tlv_off;

    BOOT_LOG_DBG("> bootutil_img_hash") ;

    // TODO: run-time multi-image
//#if (BOOT_IMAGE_NUMBER == 1) || !defined(MCUBOOT_ENC_IMAGES)
    (void)enc_state;
    (void)image_index;
    (void)hdr_size;
    (void)blk_off;
    (void)tlv_off;
//#endif

#ifdef MCUBOOT_ENC_IMAGES
    /* Encrypted images only exist in the secondary slot */
    if (MUST_DECRYPT(fap, image_index, hdr) &&
            !boot_enc_valid(enc_state, image_index, fap)) {

        BOOT_LOG_DBG("< bootutil_img_hash: boot_enc_valid = FALSE") ;
        return -1;
    }
#endif
    psa_status_t psa_ret;

    psa_ret = bootutil_sha256_init(&sha256_ctx);

    if(0 == psa_ret)
    {
        /* in some cases (split image) the hash is seeded with data from
         * the loader image */
        if (seed && (seed_len > 0)) {
        	psa_ret = bootutil_sha256_update(&sha256_ctx, seed, seed_len);
        }

        if(0 == psa_ret)
        {

            /* Hash is computed over image header and image itself. */
            size = hdr_size = hdr->ih_hdr_size;
            size += hdr->ih_img_size;
            tlv_off = size;

            /* If protected TLVs are present they are also hashed. */
            size += hdr->ih_protect_tlv_size;

            for (off = 0; off < size; off += blk_sz) {
                blk_sz = size - off;
                if (blk_sz > tmp_buf_sz) {
                    blk_sz = tmp_buf_sz;
                }
#ifdef MCUBOOT_ENC_IMAGES
                /* The only data that is encrypted in an image is the payload;
                 * both header and TLVs (when protected) are not.
                 */
                if ((off < hdr_size) && ((off + blk_sz) > hdr_size)) {
                    /* read only the header */
                    blk_sz = hdr_size - off;
                }
                if ((off < tlv_off) && ((off + blk_sz) > tlv_off)) {
                    /* read only up to the end of the image payload */
                    blk_sz = tlv_off - off;
                }
#endif
                rc = flash_area_read(fap, off, tmp_buf, blk_sz);
                if (rc) {
                    return rc;
                }
#ifdef MCUBOOT_ENC_IMAGES
                if (MUST_DECRYPT(fap, image_index, hdr)) {
                    /* Only payload is encrypted (area between header and TLVs) */
                    if (off >= hdr_size && off < tlv_off) {
                        blk_off = (off - hdr_size) & 0xf;
                        boot_encrypt(enc_state, image_index, fap, off - hdr_size,
                                blk_sz, blk_off, tmp_buf);
                    }
                }
#endif
                psa_ret = bootutil_sha256_update(&sha256_ctx, tmp_buf, blk_sz);
            }
            if (psa_ret == PSA_SUCCESS)
            {
                psa_ret = bootutil_sha256_finish(&sha256_ctx, hash_result);
            }
        }
    }

    BOOT_LOG_DBG("< bootutil_img_hash") ;

    return (int)psa_ret;
}

/*
 * Currently, we only support being able to verify one type of
 * signature, because there is a single verification function that we
 * call.  List the type of TLV we are expecting.  If we aren't
 * configured for any signature, don't define this macro.
 */
#if (defined(MCUBOOT_SIGN_RSA)      + \
     defined(MCUBOOT_SIGN_EC)       + \
     defined(MCUBOOT_SIGN_EC256)    + \
     defined(MCUBOOT_SIGN_ED25519)) > 1
#error "Only a single signature type is supported!"
#endif

#if defined(MCUBOOT_SIGN_RSA)
#    if MCUBOOT_SIGN_RSA_LEN == 2048
#        define EXPECTED_SIG_TLV IMAGE_TLV_RSA2048_PSS
#    elif MCUBOOT_SIGN_RSA_LEN == 3072
#        define EXPECTED_SIG_TLV IMAGE_TLV_RSA3072_PSS
#    else
#        error "Unsupported RSA signature length"
#    endif
#    define SIG_BUF_SIZE (MCUBOOT_SIGN_RSA_LEN / 8)
#    define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE) /* 2048 bits */
#elif defined(MCUBOOT_SIGN_EC)
#    define EXPECTED_SIG_TLV IMAGE_TLV_ECDSA224
#    define SIG_BUF_SIZE 128
#    define EXPECTED_SIG_LEN(x) ((x) >= 64) /* oids + 2 * 28 bytes */
#elif defined(MCUBOOT_SIGN_EC256)
#    define EXPECTED_SIG_TLV IMAGE_TLV_ECDSA256
#    define SIG_BUF_SIZE 128
/* DER signature representation
 *
 * 0x30 - DER prefix
 * 0x45 - Length of rest of Signature
 * 0x02 - Marker for r value
 * 0x21 - Length of r value (0x20 or 0x21)
 * 00ed...8f - r value, Big Endian
 * 0x02 - Marker for s value
 * 0x21 - Length of s value (0x20 or 0x21)
 * 7a98...ed - s value, Big Endian
 * len = [70..72]
 * */
#    define EXPECTED_SIG_LEN(x) ((x) >= 70) /* oids + 2 * 32 bytes */
#elif defined(MCUBOOT_SIGN_ED25519)
#    define EXPECTED_SIG_TLV IMAGE_TLV_ED25519
#    define SIG_BUF_SIZE 64
#    define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE)
#else
#    define SIG_BUF_SIZE 32 /* no signing, sha256 digest only */
#endif

/**
 * Reads the value of an image's selected TLV tag
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param security_cnt  Pointer to store the resultvalue.
 *
 * @return              0 on success; nonzero on failure.
 */
static int
bootutil_get_tag_value(struct image_header *hdr,
                              const struct flash_area *fap,
                              uint16_t tag_id,
                              void *tag_value, uint16_t tag_len)
{
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    uint32_t found = 0;
    int32_t rc;

    if ((hdr == NULL) ||
        (fap == NULL) ||
        (tag_value == NULL)) {
        /* Invalid parameter. */
        return BOOT_EBADARGS;
    }

    /* The security counter TLV is in the protected part of the TLV area. */
    if (hdr->ih_protect_tlv_size == 0) {
        return BOOT_EBADIMAGE;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, tag_id, true);
    if (rc) {
        return rc;
    }

    /* Traverse through the protected TLV area to find
     * the security counter TLV.
     */
    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
        if (rc < 0) {
            return -1;
        } else if (rc > 0) {
            break;
        }

        if (len != tag_len) {
            /* Value size is not valid. */
            return BOOT_EBADIMAGE;
        }

        rc = flash_area_read(fap, off, tag_value, len);
        if (rc != 0) {
            return BOOT_EFLASH;
        }

        /* Security counter has been found. */
        found = 1;
        break;
    }

    if (found) {
        return 0;
    }

    return -1;
}

#ifdef MCUBOOT_HW_ROLLBACK_PROT
/**
 * Reads the value of an image's security counter.
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param security_cnt  Pointer to store the security counter value.
 *
 * @return              0 on success; nonzero on failure.
 */
int32_t
bootutil_get_img_security_cnt(struct image_header *hdr,
                              const struct flash_area *fap,
                              uint32_t *img_security_cnt)
{
    int rc = -1;
    uint32_t security_cnt = 0;

    /* clear the destination variable */
    *img_security_cnt = 0;

    rc = bootutil_get_tag_value(hdr, fap, IMAGE_TLV_SEC_CNT, (void *)&security_cnt, sizeof(uint32_t));

    if ((rc == 0) && ((uint32_t)security_cnt <= 255UL))
    {
        /* update the destination variable */
        *img_security_cnt = security_cnt;
        rc = 0;
    }
    else
    {
        /* Security counter is not valid. */
        BOOT_LOG_DBG("Invalid security counter TLV value = %d", (int)security_cnt);
    }

    return rc;
}
#endif /* MCUBOOT_HW_ROLLBACK_PROT */

/*
 * Verify the integrity of the image.
 * Return non-zero if image could not be validated/does not validate.
 */
int
bootutil_img_validate(struct enc_key_data *enc_state, int image_index,
                      struct image_header *hdr, const struct flash_area *fap,
                      uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *seed,
                      int seed_len, uint8_t *out_hash)
{
    uint32_t off;
    uint16_t len;
    uint16_t type;
    int valid_sha256 = 0;
    int valid_image_id = 0;
#ifdef EXPECTED_SIG_TLV
    int valid_signature = 0;
    int key_id = 0;
#endif
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE];
    uint8_t hash[32];
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    uint32_t security_cnt = IMAGE_CY_SEC_CNT_MAX_VALUE;
    uint32_t img_security_cnt = 0UL;
    int valid_security_counter = 0;
#endif
    int slot_id = -1;
    int rc = -1;

    uint8_t image_id = 0u;

    BOOT_LOG_DBG("> Validate image, index = %d", (int)image_index);

    /* Get boolean image encrypted status from the header flags */
    bool is_image_encrypted = (IS_ENCRYPTED(hdr) > 0);

    /* Check image encrypted status only for UPGRADE slots */
    slot_id = cy_bootutil_get_slot_id(fap);
    if (slot_id < 0) {
        return rc;
    }
    else
    if (slot_id > 0)
    {
        /* Check for upgrade is enabled in the policy */
        rc = cy_bootutil_check_upgrade(fap);
        if (rc < 0) {
            return rc;
        }

        /* Check if encrypted status in the image does match to the policy */
        if ( is_image_encrypted != (bool)cy_bootutil_get_image_encrypt(fap))
        {
            BOOT_LOG_DBG(" * Image encryption (%d) does not match the policy (%d), index = %d", (int)IS_ENCRYPTED(hdr), cy_bootutil_get_image_encrypt(fap), (int)image_index);

            //TODO: Enhance a policy checking
            return -1;
        }

        BOOT_LOG_DBG(" * call bootutil_img_hash");

        rc = bootutil_img_hash(enc_state, image_index, hdr, fap, tmp_buf, tmp_buf_sz, hash, seed, seed_len);
        if (rc) {
            return rc;
        }

    }
    else
    {
        /* calculate the image hash in the boot slot */
        BOOT_LOG_DBG(" * call bootutil_rawimg_hash");

        rc = bootutil_rawimg_hash(enc_state, image_index, hdr, fap, hash, seed, seed_len);
        if (rc) {
            return rc;
        }
    }

    if (out_hash) {
        memcpy(out_hash, hash, 32);
    }

    /*
     * Traverse through all of the TLVs, performing any checks we know
     * and are able to do.
     */
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
    if (rc) {
        return rc;
    }

    while (true)
    {
        rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            return -1;
        } else if (rc > 0) {
            break;
        }

        switch (type)
        {
            case IMAGE_TLV_CYSB_IMAGE_ID:
                rc = flash_area_read(fap, off, &image_id, len);
                if (rc) {
                    return rc;
                }

                /* Check for image ID is equal to ID from the policy */
                rc = cy_bootutil_check_image_id(fap, image_id);
                if (rc) {
                    return -1;
                }

                BOOT_LOG_DBG(" * Check image ID, index = %d, ID = %d", (int)image_index, (int)image_id);

                valid_image_id = 1;

                break;
            case IMAGE_TLV_SHA256:
                {
                    /*
                     * Verify the SHA256 image hash.  This must always be
                     * present.
                     */
                    if (len == sizeof(hash)) {

                        rc = flash_area_read(fap, off, buf, sizeof hash);
                        if (rc) {
                            return rc;
                        }

                        rc = memcmp(hash, buf, sizeof(hash));
                        if (rc == 0) {
                            valid_sha256 = 1;
                        }
                    }
                }
                break;
        #ifdef EXPECTED_SIG_TLV
            case IMAGE_TLV_KEYHASH:
                /*
                * Not used in CypressBootloader because 
                * it has keys stored in isolated key 
                * storage (HW Key).
                */
                break;
            case EXPECTED_SIG_TLV:
                {
#ifdef MCUBOOT_HW_KEY
                    key_id = cy_bootutil_get_image_sign_key(fap);
#else
#error "Only HW KEY is supported by CypressBootloader."
#endif
                    /* Ignore this signature if it is out of bounds. */
                    if (key_id <= 0 || key_id > (int)CY_FB_MAX_KEY_COUNT) {
                        key_id = -1;
                        continue;
                    }
                    if (!EXPECTED_SIG_LEN(len) || len > sizeof(buf)) {
                        return -1;
                    }
                    rc = flash_area_read(fap, off, buf, len);
                    if (rc) {
                        return -1;
                    }

                    rc = bootutil_verify_sig(hash, sizeof(hash), buf, len, key_id);
                    if (rc == 0) {
                        valid_signature = 1;
                    }
                    key_id = 0;
                }
                break;
        #endif /* EXPECTED_SIG_TLV */
        #ifdef MCUBOOT_HW_ROLLBACK_PROT
            case IMAGE_TLV_SEC_CNT:
                {
                    /*
                     * Verify the image's security counter.
                     * This must always be present.
                     */
                    if (len != sizeof(img_security_cnt)) {
                        /* Security counter is not valid. */
                        BOOT_LOG_DBG("Invalid security counter TLV size, image ID = %d", (int)image_id);
                        return -1;
                    }

                    rc = flash_area_read(fap, off, &img_security_cnt, len);
                    if (rc) {
                        return rc;
                    }

                    if ((uint32_t)img_security_cnt > IMAGE_CY_SEC_CNT_MAX_VALUE)
                    {
                        /* Security counter is not valid. */
                        BOOT_LOG_DBG(" * Invalid security counter TLV value = %d, image ID = %d", (int)img_security_cnt, (int)image_id);
                        return -1;
                    }

                    rc = boot_nv_security_counter_get(image_index, &security_cnt);
                    if (rc != 0) {
                        return rc;
                    }

                    if ((uint32_t)security_cnt > IMAGE_CY_SEC_CNT_MAX_VALUE)
                    {
                        /* Security counter is not valid. */
                        BOOT_LOG_DBG(" * Invalid security counter stored value = %d, image ID = %d", (int)security_cnt, (int)image_id);

                        security_cnt = IMAGE_CY_SEC_CNT_MAX_VALUE;

                        return -1;
                    }

                    /* Compare the new image's security counter value against the
                     * stored security counter value.
                     */
                    if ((uint32_t)img_security_cnt >= (uint32_t)security_cnt) {
                        /* The image's security counter has been successfully verified. */
                        valid_security_counter = 1;
                    }
                }
                break;
#endif /* MCUBOOT_HW_ROLLBACK_PROT */
            default:
                break;
        }
    }

    if (!valid_sha256) {
        BOOT_LOG_DBG(" * Invalid SHA256 digest of bootable image, ID = %d", (int)image_id);
        return -1;
    }

    if (!valid_image_id) {
        BOOT_LOG_DBG(" * Invalid image ID of bootable image, ID = %d", (int)image_id);
        return -1;
    }
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    if (!valid_security_counter) {
        /* The image's security counter is not accepted. */
        BOOT_LOG_DBG(" * Invalid secure counter of bootable image, ID = %d, image cnt(%d) < stored cnt(%d)", (int)image_id, (int)img_security_cnt, (int)security_cnt);
        return -1;
    }
#endif

#ifdef EXPECTED_SIG_TLV
    if (!valid_signature) {
        BOOT_LOG_DBG(" * Invalid signature of bootable image, ID = %d", (int)image_id);
        return -1;
    }
#endif

    BOOT_LOG_DBG("< Image validated successfully, ID = %d, index = %d", (int)image_id, (int)image_index);

    return 0;
}
