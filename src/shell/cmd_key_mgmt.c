/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/error.h"
#include <zephyr.h>
#include "shell/cmd_key_mgmt.h"
#include <logging/log_ctrl.h>
#include <logging/log.h>
/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);
#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

psa_status_t psa_get_uuid(unsigned char *uuid, size_t uuid_size)
{
	psa_status_t status;

	// Request device UUID (derived at startup from the HUK)
	status = al_psa_status(
		psa_huk_key_derivation_generate_uuid(uuid, uuid_size),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to get UUID.");
		return status;
	}
	return status;
}

#endif
