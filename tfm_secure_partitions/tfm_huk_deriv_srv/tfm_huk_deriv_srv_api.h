/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TFM_HUK_DERIV_SRV_API_H__
#define __TFM_HUK_DERIV_SRV_API_H__

#include <stddef.h>
#include <stdbool.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/crypto.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_info_print(FMT, ARGS ...)		   \
	do { LOG_INFFMT("[%s] " FMT "\n", \
			SERV_NAME, ## ARGS); } while (0)

#define log_err_print(FMT, ARGS ...)						\
	do { LOG_ERRFMT("[%s] <err> %s:%s():%d " FMT "\n",			\
			SERV_NAME, __FILENAME__,  __func__, __LINE__, ## ARGS);	\
	} while (0)

#define log_dbg_print(FMT, ARGS ...)						\
	do { LOG_DBGFMT("[%s] <err> %s:%s():%d " FMT "\n",			\
			SERV_NAME, __FILENAME__,  __func__, __LINE__, ## ARGS);	\
	} while (0)


/** Define the index for the key in the key context array. */
typedef enum {
	HUK_KEY_CLIENT_TLS = 0,                 /**< TLS client key ID */
	HUK_KEY_COSE,                           /**< COSE SIGN/Encrypt key ID */
	HUK_KEY_COUNT,                          /**< Number of keys present */
} huk_key_idx_t;

typedef enum {
	HUK_CLIENT_TLS  = 0x5001,               // Client TLS key id
	HUK_COSE        = 0x5002,               // COSE SIGN key id
} huk_key_type_t;

/** Inidicates key provisioning status. */
typedef enum {
	HUK_NONE = 0,
	HUK_KEY_GEN,            /**< Key generated */
	HUK_X_509_CERT_GEN,     /**< X.509 certificate generated */
} huk_key_stat_t;

/** Supported encoding format for the inference output. */
typedef enum {
	HUK_ENC_CBOR = 0,               /**< Request a simple CBOR payload. */
	HUK_ENC_COSE_SIGN1,             /**< Request a COSE SIGN1 payload. */
	HUK_ENC_COSE_ENCRYPT0,          /**< Request a COSE ENCRYPT0 payload. */
	HUK_ENC_NONE,
} huk_enc_format_t;

/** Key context. */
typedef struct {
	/** PSA Crypto key handle for the key in the secure domain. */
	psa_key_id_t key_id;
	/** Key status, indicate if a certificate is available. */
	huk_key_stat_t status;
} huk_key_context_t;

/**
 * \brief Generate EC Key
 *
 * Generates an EC Key
 *
 * \param[in] ec_key_id         EC key id for persistent key.
 * \param[in] hpke_info         Unique hpke_info passed to the key derivation.
 * \param[in] hpke_info_size    Unique hpke_info size in bytes.
 * \param[in] key_usage_flag    Pointer to key usage flag.
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_deriv_ec_key(psa_key_id_t *ec_key_id,
				  const uint8_t *hpke_info,
				  size_t hpke_info_size,
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
