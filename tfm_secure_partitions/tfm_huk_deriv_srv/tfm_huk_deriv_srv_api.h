/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_HUK_DERIV_SRV_API_H__
#define __TFM_HUK_DERIV_SRV_API_H__

#include <stddef.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/crypto.h"
#include <stdbool.h>

typedef enum {
	HUK_CLIENT_TLS          = 0x5001,       // Client TLS key id
	HUK_COSE_SIGN           = 0x5002,       // COSE SIGN key id
	HUK_COSE_ENCRYPT        = 0x5003,       // COSE ENCRYPT key id
} huk_key_type_t;

/** Supported encoding format for the inference output. */
typedef enum {
	HUK_ENC_CBOR = 0,               /**< Request a simple CBOR payload. */
	HUK_ENC_COSE_SIGN1,             /**< Request a COSE SIGN1 payload. */
	HUK_ENC_COSE_ENCRYPT0,          /**< Request a COSE ENCRYPT0 payload. */
} huk_enc_format_t;

/**
 * \brief Generate EC Key
 *
 * Generates an EC Key
 *
 * \param[in] ec_key_id         EC key id for persistent key.
 * \param[in] seed              Unique seed passed to the key derivation.
 * \param[in] seed_size         Unique seed size in bytes.
 * \param[in] key_usage_flag    Pointer to key usage flag.
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_deriv_ec_key(psa_key_id_t *ec_key_id,
				  const uint8_t *seed,
				  size_t seed_size,
				  psa_key_usage_t *key_usage_flag);
/**
 * \brief COSE CBOR encode and sign
 *
 * COSE CBOR encode and sign
 *
 * \param[in]  inf_value        Tflm inference value to encode and sign
 * \param[in]  cfg              Pointer to COSE CBOR config
 * \param[out] encoded_buf      Buffer to which encoded data
 *                              is written into
 * \param[out] encoded_buf_len  Encoded buffer len in bytes
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_cose_sign(float *inf_value,
			       huk_enc_format_t enc_format,
			       uint8_t *encoded_buf,
			       size_t encoded_buf_size,
			       size_t *encoded_buf_len);

#endif // __TFM_HUK_DERIV_SRV_API_H__
