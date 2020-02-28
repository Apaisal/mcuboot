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

/*******************************************************************************
* \copyright
*
* (c) 2019, Cypress Semiconductor Corporation
* or a subsidiary of Cypress Semiconductor Corporation. All rights
* reserved.
*
* This software is a port of the open source MCUBoot project.
*
* This file was modified to fit PSoC6-based MCUBoot applications.
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

#include <string.h>
#include "cy_syslib.h"
#include "cy_ipc_drv.h"
#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_SIGN_EC256
#include "bootutil/sign_key.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"

#include "flashboot_psacrypto/flashboot_psacrypto.h"
#include "psa/crypto.h"

#define PSACRYPTO_SIGN_R_OFFSET 	(4)
#define PSACRYPTO_SIGN_RS_OFFSET 	(2)
#define PSACRYPTO_SIGN_RS_SIZE 		(32)

#define PSACRYPTO_SYSCALL_OPCODE        (0x35UL << 24UL)
#define PSACRYPTO_SYSCALL_ASYM_VERIF    (0x00UL << 8UL)
#define CY_FB_SYSCALL_SUCCESS           (0xA0000000UL)
#define PSACRYPTO_SYSCALL_TIMEOUT_SHORT (15000UL)
#define PSACRYPTO_SYSCALL_TIMEOUT_LONG  (2000000000UL)

#define CY_SIG_DER_PREFIX (0x30)
#define CY_SIG_DER_MARKER (0x02)

/*
 * Declaring these like this adds NULL termination.
 */
static const uint8_t ec_pubkey_oid[] = MBEDTLS_OID_EC_ALG_UNRESTRICTED;
static const uint8_t ec_secp256r1_oid[] = MBEDTLS_OID_EC_GRP_SECP256R1;

/*
 * Parse the public key used for signing.
 */
int bootutil_parse_eckey(mbedtls_ecdsa_context *ctx, uint8_t **p, uint8_t *end)
{
    size_t len;
    mbedtls_asn1_buf alg;
    mbedtls_asn1_buf param;

    if (mbedtls_asn1_get_tag(p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return -1;
    }
    end = *p + len;

    if (mbedtls_asn1_get_alg(p, end, &alg, &param)) {
        return -2;
    }
    if (alg.len != sizeof(ec_pubkey_oid) - 1 ||
      memcmp(alg.p, ec_pubkey_oid, sizeof(ec_pubkey_oid) - 1)) {
        return -3;
    }
    if (param.len != sizeof(ec_secp256r1_oid) - 1||
      memcmp(param.p, ec_secp256r1_oid, sizeof(ec_secp256r1_oid) - 1)) {
        return -4;
    }

    if (mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1)) {
        return -5;
    }

    if (mbedtls_asn1_get_bitstring_null(p, end, &len)) {
        return -6;
    }
    if (*p + len != end) {
        return -7;
    }

    if (mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, *p, end - *p)) {
        return -8;
    }

    if (mbedtls_ecp_check_pubkey(&ctx->grp, &ctx->Q)) {
        return -9;
    }
    return 0;
}

static int Cy_SignatureDER2ASN1(uint8 *signIn, uint8 *signOut)
{
    psa_status_t psa_res = PSA_SUCCESS;

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
     * */
    int32_t r_len=0, s_len=0;
    int32_t r_offset=0, s_offset=0;

    /* check prefix */
    if(CY_SIG_DER_PREFIX != signIn[0])
    {
    	psa_res = PSA_ERROR_INVALID_SIGNATURE;
    }

    if(PSA_SUCCESS == psa_res)
    {  	/* check r-marker */
    	if(CY_SIG_DER_MARKER != signIn[2])
        {
        	psa_res = PSA_ERROR_INVALID_SIGNATURE;
        }
    }

    if(PSA_SUCCESS == psa_res)
    {
		memset(signOut, 0x00, PSACRYPTO_SIGN_RS_SIZE * 2);

		r_len = *(signIn+PSACRYPTO_SIGN_R_OFFSET-1);
		s_len = *(signIn+PSACRYPTO_SIGN_R_OFFSET+r_len+1);

		r_offset = PSACRYPTO_SIGN_R_OFFSET+r_len;
		s_offset = r_offset + PSACRYPTO_SIGN_RS_OFFSET+s_len;
    }

    if(PSA_SUCCESS == psa_res)
    {	/* check s-marker */
    	if(CY_SIG_DER_MARKER != signIn[r_offset])
        {
        	psa_res = PSA_ERROR_INVALID_SIGNATURE;
        }
    }

    if(PSA_SUCCESS == psa_res)
    {
    	/* check TLV length :
    	 * r_len - 1 byte
    	 * s_len - 1 byte
    	 * r-tag - 1 byte
    	 * s-tag - 1 byte */
    	if(signIn[1] != (r_len+s_len+4))
        {
        	psa_res = PSA_ERROR_INVALID_SIGNATURE;
        }
    }

    if(PSA_SUCCESS == psa_res)
    {
		if(r_len>PSACRYPTO_SIGN_RS_SIZE)
		{
			r_len = PSACRYPTO_SIGN_RS_SIZE;
		}
		if(s_len>PSACRYPTO_SIGN_RS_SIZE)
		{
			s_len = PSACRYPTO_SIGN_RS_SIZE;
		}

		while(r_len > 0)
		{
			signOut[PSACRYPTO_SIGN_RS_SIZE - r_len] = signIn[r_offset - r_len];
			r_len--;
		}
		while(s_len > 0)
		{
			signOut[(PSACRYPTO_SIGN_RS_SIZE * 2) - s_len] = signIn[s_offset - s_len];
			s_len--;
		}
		/* ASN.1 signature representation
		 *
		 * ECDSASignature ::= SEQUENCE
		 * {
		 *      r   INTEGER,
		 *      s   INTEGER
		 * }
		 * */
    }
    return psa_res;
}

#if defined(MCUBOOT_USE_FLASHBOOT_CRYPTO)
int
bootutil_verify_sig(uint8_t *hash, uint32_t hlen, uint8_t *sig, size_t slen,
        uint8_t key_id)
{
    uint8_t signature[PSACRYPTO_SIGN_RS_SIZE * 2];
    psa_status_t psa_res;
    fb_psa_key_handle_t key_handle;

    /* Suppress unused variable warnings */
    (void)hlen;
    (void)slen;

    psa_res = Cy_SignatureDER2ASN1(sig, signature);

    if(PSA_SUCCESS == psa_res)
    {
        psa_res = fb_keys_open_key(key_id, &key_handle);
    }

    if(PSA_SUCCESS == psa_res)
    {
		psa_res = fb_psa_asymmetric_verify(key_handle,                  /* key_handle */
										PSA_ALG_ECDSA(PSA_ALG_SHA_256), /* algorithm */
										hash,                           /* hash[] */
										32,                             /* hash_length */
										(const uint8_t *)signature,     /* signature[]  */
										PSACRYPTO_SIGN_RS_SIZE * 2      /* signature_length */
										);
    }

    return (int)psa_res;
}
#else  /* #ifdef (MCUBOOT_USE_FLASHBOOT_CRYPTO) */
int
bootutil_verify_sig(uint8_t *hash, uint32_t hlen, uint8_t *sig, size_t slen,
  uint8_t key_id)
{
    uint8_t signature[PSACRYPTO_SIGN_RS_SIZE * 2];
    /* expect 128 bytes is enough for ECC public key to be stored */
    uint8_t key_data[128];
    size_t key_data_length;

    psa_key_policy_t policy;
    psa_status_t psa_res;
    int key = key_id;

    /* There is no key stored anywhere except key storage in SecureFlashBoot.
     * So need to extract key data from it via SysCall. */
    psa_res = fb_psa_export_public_key(key, key_data, 128, &key_data_length);

    if(PSA_SUCCESS == psa_res)
    {
		psa_crypto_init();
		psa_key_policy_init( &policy );
		psa_key_policy_set_usage( &policy,
									PSA_KEY_USAGE_VERIFY,
									PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_res = psa_set_key_policy( key, &policy );
    }

    if(PSA_SUCCESS == psa_res)
    {
        /*
        * \param key         Slot where the key will be stored. This must be a
        *                    valid slot for a key of the chosen type. It must
        *                    be unoccupied.
        * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
        * \param[in] data    Buffer containing the key data.
        * \param data_length Size of the \p data buffer in bytes.
        */
    	/* Re-import secure FlashBoot key into local storage */
        psa_res = psa_import_key( key,
                                PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1),
								key_data,
								key_data_length);

		/* Once imported - clean sensitive cryptographic data */
		memset(key_data, 0x00, sizeof(key_data));
    }

    if(PSA_SUCCESS == psa_res)
    {
        psa_res = Cy_SignatureDER2ASN1(sig, signature);
    }

    if(PSA_SUCCESS == psa_res)
    {


        psa_res = psa_asymmetric_verify(key,                            /* key_id */
                                        PSA_ALG_ECDSA(PSA_ALG_SHA_256), /* algorithm */
                                        hash,                           /* hash[] */
                                        32,                             /* hash_length */
                                        (const uint8_t *)signature,     /* signature[]  */
                                        PSACRYPTO_SIGN_RS_SIZE * 2      /* signature_length */
                                        );

		/* clean sensitive cryptographic data unconditionally */
		(void)psa_destroy_key(key);
    }
    return (int)psa_res;
}
#endif /* #if defined (MCUBOOT_USE_FLASHBOOT_CRYPTO) */

#endif /* MCUBOOT_SIGN_EC */
