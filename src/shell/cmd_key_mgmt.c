/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "shell/cmd_key_mgmt.h"
#include "util/util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

psa_status_t psa_get_uuid(unsigned char *uuid, size_t uuid_size)
{
	psa_status_t status;

	// Request device UUID (derived at startup from the HUK)
	status = al_psa_status(
		psa_huk_get_uuid(uuid, uuid_size),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to get UUID.");
	}
	return status;
}

psa_status_t psa_get_pubkey(uint8_t *public_key, size_t public_key_len,
			    km_key_context_t ctx)
{
	psa_status_t status;

	status = al_psa_status(
		psa_huk_get_pubkey(&ctx.key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
	}
	return status;
}

#endif
