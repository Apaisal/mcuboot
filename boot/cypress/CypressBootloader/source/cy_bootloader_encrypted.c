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

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_ENC_IMAGES)
#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include <flash_map_backend/flash_map_backend.h>

#include "flashboot_psacrypto/flashboot_psacrypto.h"

#include "bootutil/image.h"
#include "bootutil/enc_key.h"

#include "bootutil_priv.h"

#include "bootutil/bootutil_log.h"

#include <stdlib.h>
#include "cy_image_utils.h"
#include "cy_secure_utils.h"

#define MBEDTLS_EC256_PUBKEY_SIZE   (64)
#define MBEDTLS_SHA256_DIGEST_SIZE  (32)
#define MBEDTLS_AES_KEY_SIZE        (16)

#define CY_IMG_CRYPTO_BLK_SIZE      MBEDTLS_AES_KEY_SIZE
#define CY_FB_AES128_KEY_LEN        MBEDTLS_AES_KEY_SIZE
#define CY_FB_AES128_IV_LEN         MBEDTLS_AES_KEY_SIZE

const uint8_t key_label[MBEDTLS_AES_KEY_SIZE] = "MCUBoot_ECIES_v1";
const uint8_t key_salt[MBEDTLS_AES_KEY_SIZE] = { 0x0 };

static fb_psa_key_handle_t aesHandle;
static fb_psa_key_policy_t aesPolicy;

static fb_psa_cipher_operation_t cipherOp = { 0x0 };

int
boot_enc_set_key(struct enc_key_data *enc_state, uint8_t slot,
        const struct boot_status *bs)
{

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    BOOT_LOG_DBG("> boot_enc_set_key") ;

    aesPolicy = fb_psa_key_policy_init();
    fb_psa_key_policy_set_usage(&aesPolicy,
                                PSA_KEY_USAGE_DECRYPT,
                                PSA_ALG_CTR);

    status = fb_psa_allocate_key(&aesHandle);
    if (PSA_SUCCESS == status)
    {
        status = fb_psa_set_key_policy(aesHandle, &aesPolicy);
    }

    /* Import AES key  */
    if (PSA_SUCCESS == status)
    {
        status = fb_psa_import_key(aesHandle,
                                PSA_KEY_TYPE_AES,
                                bs->enckey[slot],
                                CY_FB_AES128_KEY_LEN);
    }

    if (PSA_SUCCESS == status)
    {
        enc_state[slot].valid = 1;
    }

    BOOT_LOG_DBG("< boot_enc_set_key") ;

    return (int)status;
}

#define EC_PUBK_INDEX       (1)
#define EC_TAG_INDEX        (EC_PUBK_INDEX + MBEDTLS_EC256_PUBKEY_SIZE)
#define EC_CIPHERKEY_INDEX  (EC_TAG_INDEX + MBEDTLS_SHA256_DIGEST_SIZE)

#define EXPECTED_ENC_LEN    ((EC_PUBK_INDEX + MBEDTLS_EC256_PUBKEY_SIZE) + MBEDTLS_SHA256_DIGEST_SIZE + MBEDTLS_AES_KEY_SIZE)
#define EXPECTED_ENC_TLV    IMAGE_TLV_ENC_EC256

_Static_assert(EC_CIPHERKEY_INDEX + 16 == EXPECTED_ENC_LEN,
        "Please fix ECIES-P256 component indexes");

/*
 * Decrypt an encryption key TLV.
 *
 * @param buf An encryption TLV read from flash (build time fixed length)
 * @param enckey An AES-128 key sized buffer to store to plain key.
 */
static int
cy_boot_enc_decrypt(int key_id, const uint8_t *buf, uint8_t *enckey)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* AES key length + IV length */
    uint8_t derivedKey[CY_FB_AES128_KEY_LEN + MBEDTLS_SHA256_DIGEST_SIZE];
    uint8_t aesIV[CY_FB_AES128_IV_LEN] = { 0x0U };

    fb_psa_key_handle_t privateKeyHandle;
    fb_psa_key_type_t   privateKeyType;
    fb_psa_key_type_t   publicKeyType;
    fb_psa_algorithm_t  alg = 0U;
    size_t keyBits;

    uint8_t *publicKey = NULL;
    size_t publicKeyLength = 0U;

    BOOT_LOG_DBG("> boot_enc_decrypt") ;

    fb_psa_crypto_generator_t generator = { 0x0 };

    status = fb_psa_generator_setup(&generator);

    if (PSA_SUCCESS == status)
    {
        alg = PSA_ALG_ECDH(PSA_ALG_HKDF(PSA_ALG_SHA_256));
    }

    /* AES key length + IV length */
    uint32_t outSize = CY_FB_AES128_KEY_LEN + MBEDTLS_SHA256_DIGEST_SIZE;

    /*
     * First "element" in the TLV is the curve point (public key)
     */

    if (PSA_SUCCESS == status)
    {
        BOOT_LOG_DBG(" * Open a private key, id = %d ", key_id) ;

        status = fb_keys_open_key(key_id, (fb_psa_key_handle_t*)&privateKeyHandle);

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_get_key_information( privateKeyHandle, &privateKeyType, &keyBits );
        }
    }
    /* Private key is successfully loaded now to d */

    if (PSA_SUCCESS == status)
    {
        BOOT_LOG_DBG(" * Load a public key") ;

        status = PSA_ERROR_INVALID_ARGUMENT;

        /* Check ASN tag to ensure that EC point is in uncompressed binary format */
        if (0x04 == buf[0])
        {
            publicKeyType = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR( privateKeyType );
            publicKeyLength = PSA_KEY_EXPORT_MAX_SIZE( publicKeyType, keyBits );

            publicKey = malloc(publicKeyLength);

            if (publicKey == NULL)
            {
                status = PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            else
            {
                memcpy(publicKey, buf, publicKeyLength);

                status = PSA_SUCCESS;
            }
        }
    }
    /* Public key is successfully loaded now to P */

    /*
     * Expand shared secret to create keys for AES-128-CTR + HMAC-SHA256
     */
    if (PSA_SUCCESS == status)
    {
        BOOT_LOG_DBG(" * Expand a shared secret to create AES and HMAC keys") ;

        status = fb_psa_key_agreement_salt_label( &generator,
                                                  privateKeyHandle,
                                                  publicKey, publicKeyLength,
                                                  alg,
                                                  key_salt,  CY_IMG_CRYPTO_BLK_SIZE,
                                                  key_label, CY_IMG_CRYPTO_BLK_SIZE
                                                );

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_generator_read( &generator, derivedKey, outSize );
        }
    }
    if(status == PSA_SUCCESS)
    {
        status = fb_psa_export_public_key(privateKeyHandle, publicKey, publicKeyLength, &publicKeyLength);
    }
    
    if (publicKey != NULL)
    {
        memset( publicKey, 0, publicKeyLength);
        free( publicKey );
    }

    /*
     * HMAC the key and check that our received MAC matches the generated tag
     */
    if (PSA_SUCCESS == status)
    {
        BOOT_LOG_DBG(" * Check HMAC of the cipher key") ;

        fb_psa_mac_operation_t macOper = { 0x0 };
        fb_psa_key_handle_t macHandle;
        fb_psa_key_policy_t macPolicy;

        macPolicy = fb_psa_key_policy_init();
        fb_psa_key_policy_set_usage(&macPolicy,
                                    PSA_KEY_USAGE_VERIFY,
                                    PSA_ALG_HMAC(PSA_ALG_SHA_256));

        status = fb_psa_allocate_key(&macHandle);

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_set_key_policy(macHandle, &macPolicy);
        }

        /* Import HMAC key  */
        if (PSA_SUCCESS == status)
        {
            status = fb_psa_import_key(macHandle,
                                       PSA_KEY_TYPE_HMAC,
                                       &derivedKey[CY_FB_AES128_KEY_LEN],
                                       MBEDTLS_SHA256_DIGEST_SIZE);
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_mac_verify_setup(&macOper, macHandle, PSA_ALG_HMAC(PSA_ALG_SHA_256));
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_mac_update(&macOper, &buf[EC_CIPHERKEY_INDEX], BOOT_ENC_KEY_SIZE);
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_mac_verify_finish(&macOper, &buf[EC_TAG_INDEX], MBEDTLS_SHA256_DIGEST_SIZE);
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_destroy_key(macHandle);
        }
    }

    /*
     * Finally decrypt the received ciphered key
     */
    if (PSA_SUCCESS == status)
    {
        BOOT_LOG_DBG(" * Decrypt an image encrypting AES key") ;

        aesPolicy = fb_psa_key_policy_init();
        fb_psa_key_policy_set_usage( &aesPolicy,
                                    PSA_KEY_USAGE_DECRYPT,
                                    PSA_ALG_CTR);

        status = fb_psa_allocate_key(&aesHandle);
        if (PSA_SUCCESS == status)
        {
            status = fb_psa_set_key_policy(aesHandle, &aesPolicy);
        }

        /* Import AES key  */
        if (PSA_SUCCESS == status)
        {
            status = fb_psa_import_key(aesHandle,
                                       PSA_KEY_TYPE_AES,
                                       derivedKey,
                                       CY_FB_AES128_KEY_LEN);
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_cipher_decrypt_setup(&cipherOp, aesHandle, PSA_ALG_CTR);
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_cipher_set_iv(&cipherOp,                   /* operation, */
                                          aesIV,                       /* iv, */
                                          CY_FB_AES128_IV_LEN          /* iv_length */ );
        }

        if (PSA_SUCCESS == status)
        {
            /* Decrypt and Read decryption AES KEY */
            status = fb_psa_cipher_update(&cipherOp,                    /* operation, */
                                          (const uint8_t *)&buf[EC_CIPHERKEY_INDEX], /* input, */
                                          BOOT_ENC_KEY_SIZE,            /* input_length, */
                                          enckey,                       /* output, */
                                          BOOT_ENC_KEY_SIZE,            /* output_size, */
                                          (size_t *)&outSize            /* output_length */ );

            if(BOOT_ENC_KEY_SIZE != outSize)
            {
                status = PSA_ERROR_GENERIC_ERROR;
            }
        }

        if (PSA_SUCCESS == status)
        {
            /* Close decrypt operation  */
            status = fb_psa_cipher_finish(&cipherOp,                    /* operation, */
                                        NULL,                           /* output, */
                                        0,                              /* output_size, */
                                        (size_t *)&outSize              /* output_length*/ );
        }

        if (PSA_SUCCESS == status)
        {
            status = fb_psa_destroy_key(aesHandle);
        }
    }

    BOOT_LOG_DBG("< boot_enc_decrypt, status = %08x", (int)status);

    return (int)status;
}

/*
 * Load encryption key.
 */
int
boot_enc_load(struct enc_key_data *enc_state, int image_index,
        const struct image_header *hdr, const struct flash_area *fap,
        struct boot_status *bs)
{
    (void)image_index;

    uint32_t off;
    uint16_t len;
    struct image_tlv_iter it;
    uint8_t buf[EXPECTED_ENC_LEN];
    int slot;
    int key_id = 0;
    int rc;

    BOOT_LOG_DBG("> boot_enc_load") ;

    if (cy_bootutil_get_image_encrypt(fap) == 0)
    {
        BOOT_LOG_ERR(" * Image encryption is not allowed in the policy");
        return -1;
    }

    slot = cy_bootutil_get_slot_id(fap);
    if (slot < 0) {
        return slot;
    }

    /* Already loaded... */
    if (enc_state[slot].valid) {
        BOOT_LOG_DBG("< boot_enc_load: key already loaded, exit") ;
        return 1;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, EXPECTED_ENC_TLV, false);
    if (rc != 0) {
        return -1;
    }

    BOOT_LOG_DBG(" * EXPECTED_ENC_TLV (0x32) found") ;

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        return rc;
    }

    if (len != EXPECTED_ENC_LEN) {
        return -1;
    }

    BOOT_LOG_DBG(" * Load encrypted data from TLV(0x32)") ;

    rc = flash_area_read(fap, off, buf, EXPECTED_ENC_LEN);
    if (rc != 0) {
        return -1;
    }

    key_id = cy_bootutil_get_image_enc_key(fap);

    BOOT_LOG_DBG(" * encryption key id = %d", (int)key_id);

    /* Ignore this key if it is out of bounds. */
    if (key_id <= 0 || key_id > (int)CY_FB_MAX_KEY_COUNT) {
        BOOT_LOG_DBG(" * encryption key id is invalid, break");
        return -1;
    }

    rc = cy_boot_enc_decrypt(key_id, buf, bs->enckey[slot]);

    BOOT_LOG_DBG("< boot_enc_load, rc = %d", (int)rc);

    return rc;
}

bool
boot_enc_valid(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap)
{
    int rc;

    BOOT_LOG_DBG("> boot_enc_valid");

    (void)image_index;

    rc = cy_bootutil_get_slot_id(fap);
    if (rc < 0) {
        /* can't get proper slot number - skip encryption, */
        /* postpone the error for a upper layer */
        return false;
    }

    BOOT_LOG_DBG("< boot_enc_valid: enc_state[rc].valid = %d", (int)enc_state[rc].valid);

    return enc_state[rc].valid;
}

/*
 * Image decrypt
 */
void
boot_encrypt(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap, uint32_t off, uint32_t sz,
        uint32_t blk_off, uint8_t *buf)
{

    (void)image_index;
    (void)blk_off;

    uint8_t nonce[16];
    size_t outSize;
    int rc;
    psa_status_t status = PSA_SUCCESS;

    memset( nonce, 0, 12);
    off >>= 4;
    nonce[12] = (uint8_t)(off >> 24);
    nonce[13] = (uint8_t)(off >> 16);
    nonce[14] = (uint8_t)(off >> 8);
    nonce[15] = (uint8_t)off;

    rc = cy_bootutil_get_slot_id(fap);
    if (rc < 0) {
        assert(0);
        return;
    }

    assert(enc_state[rc].valid == 1);

    if (PSA_SUCCESS == status)
    {
        status = fb_psa_cipher_decrypt_setup(&cipherOp, aesHandle, PSA_ALG_CTR);
    }

    if (PSA_SUCCESS == status)
    {
        status = fb_psa_cipher_set_iv(&cipherOp,                    /* operation, */
                                    nonce,                          /* iv, */
                                    CY_FB_AES128_IV_LEN             /* iv_length */ );
    }

    if (PSA_SUCCESS == status)
    {
        /* Decrypt and Read decryption AES KEY */
        status = fb_psa_cipher_update(&cipherOp,                    /* operation, */
                                      (const uint8_t *)buf,         /* input, */
                                      sz,                           /* input_length, */
                                      buf,                          /* output, */
                                      sz,                           /* output_size, */
                                      (size_t *)&outSize            /* output_length */ );

        if (sz != outSize)
        {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }

    if (PSA_SUCCESS == status)
    {
        /* Close decrypt operation  */
        status = fb_psa_cipher_finish(&cipherOp,                    /* operation, */
                                      NULL,                         /* output, */
                                      0,                            /* output_size, */
                                      (size_t *)&outSize            /* output_length*/ );
    }
}

/**
 * Clears encrypted state after use.
 */
void
boot_enc_zeroize(struct enc_key_data *enc_state)
{
    BOOT_LOG_DBG("> boot_enc_zeroize");

    (void)Cy_Utils_Memset( enc_state, 0, sizeof(struct enc_key_data) * BOOT_NUM_SLOTS );

    BOOT_LOG_DBG("< boot_enc_zeroize");
}

#endif /* MCUBOOT_ENC_IMAGES */
