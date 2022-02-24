/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

/* Custom secure service APIs */
#include "tfm_sp_inf/tfm_sip_srv_api.h"

#include "keys/key_mgmt.h"

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT
#include "util/util_app_log.h"
#include "shell/cmd_key_mgmt.h"
#endif

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

void main(void)
{
	psa_status_t status;
	unsigned char uuid[37];

	/* Initialise the logger subsys and dump the current buffer. */
	log_init();

	/* Initialise they key context with the required keys. */
	km_context_init(km_context_get());

	/* Initialise the inferrence model context. */
	infer_model_ctx_init(get_infer_model_context());

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT
	/* Request the device UUID, which will cache it for later requests. */
	status = al_psa_status(psa_get_uuid(uuid, sizeof(uuid)), __func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to read UUID.");
		return;
	}
#endif
}
