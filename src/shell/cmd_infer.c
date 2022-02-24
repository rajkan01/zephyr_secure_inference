/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/error.h"
#include <zephyr.h>
#include "shell/cmd_infer.h"
#include <logging/log_ctrl.h>
#include <logging/log.h>

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT
psa_status_t psa_verify_sign(uint8_t *infval_enc_buf,
			     size_t infval_enc_buf_len,
			     uint8_t *pubkey,
			     size_t pubkey_len,
			     float *out_val)
{
	uint8_t *dec;
	size_t len_dec;
	cose_sign_context_t ctx;
	int status;

	status = mbedtls_ecp_load_pubkey(&ctx.pk,
					 pubkey,
					 pubkey_len);
	if (status != 0) {
		LOG_ERR("Load the public key failed\n");
		goto err;
	}

	status = cose_sign_init(&ctx);
	if (status != COSE_ERROR_NONE) {
		LOG_ERR("Failed to initialize COSE signing context.\n");
		goto err;
	}

	status = cose_verify_sign1(&ctx,
				   infval_enc_buf,
				   infval_enc_buf_len,
				   (const uint8_t **) &dec,
				   &len_dec);
	if (status != COSE_ERROR_NONE) {
		LOG_ERR("Failed to authenticate signature.\n");
		goto err;
	}

	status = cose_payload_decode(dec, len_dec, out_val);
	if (status != COSE_ERROR_NONE) {
		LOG_ERR("Failed to decode payload.\n");
		goto err;
	}
	return status;
err:
	al_dump_log();
	cose_sign_free(&ctx);
	return status;
}

psa_status_t psa_get_infer(psa_key_id_t key_id,
			   float input,
			   uint8_t *infval_enc_buf,
			   size_t infval_enc_buf_size,
			   size_t *infval_enc_buf_len)
{
	psa_status_t status;

	status = al_psa_status(
		psa_si_tflm_hello(&key_id,
				  &input,
				  sizeof(input),
				  infval_enc_buf,
				  infval_enc_buf_size,
				  infval_enc_buf_len),
		__func__);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to get sine value using secure inference");
	}

	return status;
}
#endif
