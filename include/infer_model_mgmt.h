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
 * @brief Initialise the inference engine context to interact with the
 *        secure inference service. This allows us to send requests to any
 *        models available in the secure partition.
 *
 */
void infer_model_init(void);

#endif /* INFER_MODEL_MGMT_H */
