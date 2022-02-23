/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

#include <tfm_veneers.h>
#include <tfm_ns_interface.h>
#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "cose/cose_verify.h"
#include "util/util_app_log.h"
#include "util/util_sformat.h"
#include "pk/pk_import_verify_sign.h"
#include <math.h>
#include "shell/cmd_key_mgmt.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

void key_context_init(key_context_t *ctx)
{
	uint8_t public_key[65] = { 0 }; /* EC public key = 65 bytes. */
	size_t public_key_len = sizeof(public_key);
	psa_status_t status;
	/* String format output config. */
	struct sf_hex_tbl_fmt fmt = {
		.ascii = true,
		.addr_label = true,
		.addr = 0
	};

	ctx[0].key_id = CLIENT_TLS;
	strcpy(ctx[0].label, "Device Client TLS");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[0].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[0].status = KEY_GEN;
	}

	printf("%s public key\n", ctx[0].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

	ctx[1].key_id = C_SIGN;
	strcpy(ctx[1].label, "Device COSE SIGN");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[1].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[1].status = KEY_GEN;
	}

	printf("%s public key\n", ctx[1].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

	ctx[2].key_id = C_ENCRYPT;
	strcpy(ctx[2].label, "Device COSE ENCRYPT");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[2].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[2].status = KEY_GEN;
	}

	printf("%s public key\n", ctx[2].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

err:
	/* Dump any queued log messages, and wait for system events. */
	al_dump_log();
}

void main(void)
{
	psa_status_t status;

	/* Initialise the logger subsys and dump the current buffer. */
	log_init();

	unsigned char uuid[37];
	key_context_init(get_key_context());
	infer_model_ctx_init(get_infer_model_context());

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT
	// Generate UUID
	status = al_psa_status(
		psa_get_uuid(uuid, sizeof(uuid)),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to get UUID.");
		return;
	}
#endif  /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
}
