/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INFER_MODEL_MGMT_H
#define INFER_MODEL_MGMT_H

#include <zephyr.h>

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
 * @brief Get the inference model context
 *
 * @return Returns pointer to the inference model context
 *
 */
infer_model_ctx_t *infer_model_context_get();

/**
 * @brief Initialize the inference model context
 *
 * @param ctx      Pointer to inference model context.
 * @param sid      Inference service unique ID.
 * @param version  Version.
 * @param status   Model status.
 * @param label    Unique string to represent the model context.
 *
 */
void infer_model_ctx_init(infer_model_ctx_t *ctx,
			  uint32_t sid,
			  uint32_t version,
			  imdl_sts_t status,
			  unsigned char *label);

#endif /* INFER_MODEL_MGMT_H */
