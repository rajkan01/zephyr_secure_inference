/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

#include "psa_manifest/sid.h"
#include "tfm_partition_tflm.h"
#include "infer_model_mgmt.h"

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
void infer_model_ctx_init(infer_model_ctx_t *ctx,
			  uint32_t sid,
			  uint32_t version,
			  imdl_sts_t status,
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

infer_model_ctx_t *infer_model_context_get()
{
	static infer_model_ctx_t infer_model[IMDL_COUNT] = { 0 };

	return infer_model;
}

void infer_model_init()
{
	infer_model_ctx_t *ctx = infer_model_context_get();

	/* Initialise the TFLM sine wave model context. */
	infer_model_ctx_init(&ctx[IMDL_SINE],
			     TFM_TFLM_SERVICE_HELLO_SID,
			     TFM_TFLM_SERVICE_HELLO_VERSION,
			     IMDL_ACTIVE,
			     "sine");
}
