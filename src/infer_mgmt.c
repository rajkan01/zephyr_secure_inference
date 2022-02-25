/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

#include "cose/cose_verify.h"
#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "psa_manifest/sid.h"
#include "tfm_partition_tflm.h"
#include "infer_mgmt.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * @brief Initialize the supplied inference model context
 *
 * @param ctx      Pointer to inference model context to init.
 * @param sid      Inference service unique ID.
 * @param version  Version.
 * @param status   Model status.
 * @param label    Unique string to represent the model context.
 *
 */
void infer_model_ctx_init(infer_ctx_t *ctx,
			  uint32_t sid,
			  uint32_t version,
			  infer_model_sts_t status,
			  unsigned char *label)
{
	ctx->sid = sid;

	/* Assign a label within the limits of avaiable memory. */
	if (sizeof(ctx->sid_label) > (strlen(label) + 1)) {
		strcpy(ctx->sid_label, label);
	} else {
		LOG_ERR("Insufficient memory to copy model label");
	}

	ctx->version = version;
	ctx->sts = status;
}

psa_status_t infer_verify_signature(uint8_t *infval_enc_buf,
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

psa_status_t infer_get_cose_output(km_key_idx_t key_idx,
				   float input,
				   uint8_t *infval_enc_buf,
				   size_t infval_enc_buf_size,
				   size_t *infval_enc_buf_len)
{
	psa_status_t status;

	status = al_psa_status(
		psa_si_tflm_hello(&((km_context_get()[key_idx]).key_id),
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

infer_ctx_t *infer_context_get()
{
	static infer_ctx_t infer_model[INFER_MODEL_COUNT] = { 0 };

	return infer_model;
}

void infer_init()
{
	infer_ctx_t *ctx = infer_context_get();

	/* Initialise the TFLM sine wave model context. */
	infer_model_ctx_init(&ctx[INFER_MODEL_SINE],
			     TFM_TFLM_SERVICE_HELLO_SID,
			     TFM_TFLM_SERVICE_HELLO_VERSION,
			     INFER_MODEL_STS_ACTIVE,
			     "sine");
}
