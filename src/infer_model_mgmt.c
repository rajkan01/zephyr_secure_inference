/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "infer_model/infer_model_mgmt.h"
#include <logging/log.h>

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

void infer_model_ctx_init(infer_model_ctx_t *ctx,
			  uint32_t sid,
			  uint32_t version,
			  imdl_sts_t status,
			  unsigned char *label)
{
	ctx->sid = sid;
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
