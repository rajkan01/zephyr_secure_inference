/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

#include "shell/cmd_key_mgmt.h"
#include "key_mgmt.h"
#include "infer_model_mgmt.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

void main(void)
{
	psa_status_t status;
	unsigned char uuid[37];

	/* Initialise the logger subsys and dump the current buffer. */
	log_init();

	/* Initialise references to derived keys (required once before use!). */
	km_keys_init();

	/* Initialise references to the inference engine and models. */
	infer_model_init();

	/* Derive the device UUID, which will cache it for later requests. */
	status = al_psa_status(psa_get_uuid(uuid, sizeof(uuid)), __func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to read UUID.");
		return;
	}
}
