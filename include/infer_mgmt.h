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
	INFER_MODEL_TFLM_SINE = 0,              /**< TFLM sine inference model */
	INFER_MODEL_UTVM_SINE,                  /**< UTVM sine inference model */
	INFER_MODEL_COUNT,                      /**< Number of models present */
} infer_model_idx_t;

/** Inidicates inference model status. */
typedef enum {
	INFER_MODEL_STS_NOT_ACTIVE = 0,         /**< Inference model is inactive. */
	INFER_MODEL_STS_ACTIVE,                 /**< Inference model is active */
	INFER_MODEL_STS_NONE,
} infer_model_sts_t;

typedef struct {
	uint32_t sid;
	char sid_label[32];
	uint32_t version;
	infer_model_sts_t sts;
} infer_ctx_t;

/** Encoding format requested for the inference output. */
typedef enum {
	INFER_ENC_CBOR = 0,             /**< Request a simple CBOR payload. */
	INFER_ENC_COSE_SIGN1,           /**< Request a COSE SIGN1 payload. */
	INFER_ENC_COSE_ENCRYPT0,        /**< Request a COSE ENCRYPT0 payload. */
} infer_enc_t;

/* Inference config */
typedef struct {
	infer_enc_t enc_format;
	char models[32];
} infer_config_t;

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
 * @brief Requests the TFLM inference engine to generate an output value.
 *
 * @param enc_format           Inference output encoding format.
 * @param model                Pointer to the buffer stores model info.
 * @param input                The input parameter.
 * @param input_size           The input parameter size in bytes.
 * @param infval_enc_buf       Buffer for the COSE-encoded output.
 * @param inf_val_enc_buf_size Size of infval_enc_buf.
 * @param infval_enc_buf_len   Bytes written by the secure function.
 *
 * @return psa_status_t
 */
psa_status_t infer_get_tflm_cose_output(infer_enc_t enc_format,
					const char *model,
					void  *input,
					size_t input_size,
					uint8_t *infval_enc_buf,
					size_t inf_val_enc_buf_size,
					size_t *infval_enc_buf_len);

/**
 * @brief Requests the UTVM inference engine to generate an output value.
 *
 * @param enc_format           Inference output encoding format.
 * @param model                Pointer to the buffer stores model info.
 * @param input                The input parameter.
 * @param input_size           The input parameter size in bytes.
 * @param infval_enc_buf       Buffer for the COSE-encoded output.
 * @param inf_val_enc_buf_size Size of infval_enc_buf.
 * @param infval_enc_buf_len   Bytes written by the secure function.
 *
 * @return psa_status_t
 */
psa_status_t infer_get_utvm_cose_output(infer_enc_t enc_format,
					const char *model,
					void  *input,
					size_t input_size,
					uint8_t *infval_enc_buf,
					size_t inf_val_enc_buf_size,
					size_t *infval_enc_buf_len);

/**
 * @brief Function pointer to represent inference engine function call
 * (infer_get_tflm_cose_output or infer_get_utvm_cose_output) used in shell
 * infer command calls.
 *
 * @param enc_format           Inference output encoding format.
 * @param model                Pointer to the buffer stores model info.
 * @param input                The input parameter.
 * @param input_size           The input parameter size in bytes.
 * @param infval_enc_buf       Buffer for the COSE-encoded output.
 * @param inf_val_enc_buf_size Size of infval_enc_buf.
 * @param infval_enc_buf_len   Bytes written by the secure function.
 *
 * @return psa_status_t
 */
typedef psa_status_t (*infer_get_cose_output)(infer_enc_t enc_format,
					      const char *model,
					      void  *input,
					      size_t input_size,
					      uint8_t *infval_enc_buf,
					      size_t infval_enc_buf_size,
					      size_t *infval_enc_buf_len);

/**
 * @brief Get the inference model context
 *
 * @return Returns pointer to the inference model context
 */
infer_ctx_t *infer_context_get();

/**
 * @brief Initialise the inference engine context to interact with the
 *        secure inference service. This allows us to send requests to any
 *        models available in the secure partition.
 */
void infer_init(void);

#endif /* INFER_MGMT_H */
