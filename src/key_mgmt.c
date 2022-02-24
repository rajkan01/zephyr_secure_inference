/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <stdio.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

#include "keys/key_mgmt.h"
#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "util/util_app_log.h"
#include "util/util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

km_key_context_t *km_context_get()
{
	static km_key_context_t k_ctx[KEY_COUNT] = { 0 };

	return k_ctx;
}

void km_context_init(km_key_context_t *ctx)
{
	uint8_t public_key[KM_PUBLIC_KEY_SIZE] = { 0 };
	size_t public_key_len = sizeof(public_key);
	psa_status_t status;

	/* String format output config. */
	struct sf_hex_tbl_fmt fmt = {
		.ascii = true,
		.addr_label = true,
		.addr = 0
	};

	/* Populate the client TLS key context. */
	ctx[KEY_CLIENT_TLS].key_id = KEY_ID_CLIENT_TLS;
	strcpy(ctx[KEY_CLIENT_TLS].label, "Device Client TLS");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[KEY_CLIENT_TLS].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[KEY_CLIENT_TLS].status = KEY_GEN;
	}

	printf("%s public key\n", ctx[KEY_CLIENT_TLS].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

	/* Populate the COSE SIGN key context. */
	ctx[KEY_C_SIGN].key_id = KEY_ID_C_SIGN;
	strcpy(ctx[KEY_C_SIGN].label, "Device COSE SIGN");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[KEY_C_SIGN].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[KEY_C_SIGN].status = KEY_GEN;
	}
	printf("%s public key\n", ctx[KEY_C_SIGN].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

	/* Populate the COSE ENCRYPT key context. */
	ctx[KEY_C_ENCRYPT].key_id = KEY_ID_C_ENCRYPT;
	strcpy(ctx[KEY_C_ENCRYPT].label, "Device COSE ENCRYPT");
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx[KEY_C_ENCRYPT].key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx[KEY_C_ENCRYPT].status = KEY_GEN;
	}
	printf("%s public key\n", ctx[KEY_C_ENCRYPT].label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

err:
	/* Dump any queued log messages, and wait for system events. */
	al_dump_log();
}
