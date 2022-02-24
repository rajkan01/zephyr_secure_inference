/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "util/util_app_log.h"
#include "cose/cose_verify.h"
#include "keys/pk_import_verify_sign.h"
#include "util/util_app_log.h"
#include "util/util_sformat.h"
#include <math.h>

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

/**
 * @brief 
 * 
 * @param infval_enc_buf Buffer containing the COSE SIGN1 packet to verify.
 * @param infval_enc_buf_len Size of infval_enc_buf.
 * @param pubkey The raw public EC key value to use to verify the signature.
 * @param pubkey_len Size of pubkey.
 * @param out_val Results of the signature verification.
 * @return psa_status_t 
 */
psa_status_t psa_verify_sign(uint8_t *infval_enc_buf,
			     size_t infval_enc_buf_len,
			     uint8_t *pubkey,
			     size_t pubkey_len,
			     float *out_val);

/**
 * @brief Requests the inference engine to generate an output value.
 * 
 * @param key_id
 * @param input The floating point value to provide as an input.
 * @param infval_enc_buf Buffer for the COSE-encoded output.
 * @param inf_val_enc_buf_size Size of infval_enc_buf.
 * @param infval_enc_buf_len Bytes written by the secure function.
 * @return psa_status_t 
 */
psa_status_t psa_get_infer(psa_key_id_t key_id,
			   float input,
			   uint8_t *infval_enc_buf,
			   size_t inf_val_enc_buf_size,
			   size_t *infval_enc_buf_len);

#endif
