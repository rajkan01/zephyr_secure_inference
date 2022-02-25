/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INFER_MGMT_H
#define INFER_MGMT_H

#include <zephyr.h>
#include <psa/error.h>
#include "key_mgmt.h"

/** Define the index for the model in the model context array. */
typedef enum {
	IMDL_SINE = 0,                  /**< Sine inference model */
	IMDL_COUNT,                     /**< Number of models present */
} imdl_idx_t;

/** Inidicates inference model status. */
typedef enum {
	IMDL_NOT_ACTIVE = 0,            /**< The inference model is inactive. */
	IMDL_ACTIVE,                    /**< The inference model is active */
	IMDL_NONE,
} imdl_sts_t;

typedef struct {
	uint32_t sid;
	char sid_label[32];
	uint32_t version;
	imdl_sts_t sts;
} infer_model_ctx_t;

/**
 * @brief Verifies the COSE SIGN1 signature of the supplied payload.
 *
 * @param infval_enc_buf     Buffer containing the COSE SIGN1 packet to verify.
 * @param infval_enc_buf_len Size of infval_enc_buf.
 * @param pubkey             The EC pubkey to use to verify the signature.
 * @param pubkey_len         Size of pubkey.
 * @param out_val            Results of the signature verification.
 *
 * @return psa_status_t
 */
psa_status_t infer_verify_signature(uint8_t *infval_enc_buf,
				    size_t infval_enc_buf_len,
				    uint8_t *pubkey,
				    size_t pubkey_len,
				    float *out_val);

/**
 * @brief Requests the inference engine to generate an output value.
 *
 * @param key_idx              Key context index.
 * @param input                The floating point value to provide as an input.
 * @param infval_enc_buf       Buffer for the COSE-encoded output.
 * @param inf_val_enc_buf_size Size of infval_enc_buf.
 * @param infval_enc_buf_len   Bytes written by the secure function.
 *
 * @return psa_status_t
 */
psa_status_t infer_get_cose_output(km_key_idx_t key_idx,
				   float input,
				   uint8_t *infval_enc_buf,
				   size_t inf_val_enc_buf_size,
				   size_t *infval_enc_buf_len);

/**
 * @brief Get the inference model context
 *
 * @return Returns pointer to the inference model context
 */
infer_model_ctx_t *infer_model_context_get();

/**
 * @brief Initialise the inference engine context to interact with the
 *        secure inference service. This allows us to send requests to any
 *        models available in the secure partition.
 */
void infer_model_init(void);

#endif /* INFER_MGMT_H */
