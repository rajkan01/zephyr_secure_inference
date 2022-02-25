/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <logging/log.h>

#include "key_mgmt.h"
#include "tfm_partition_huk.h"
#include "util_app_log.h"
#include "util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * @brief Initialise the supplied key context, populating it via calls to
 *        the HUK key derivation service on the secure side.
 *
 *        Takes the supplied km_key_context_t reference, and populates it
 *        with the public details for the corresponding key. Specifically,
 *        it will associate a PSA key ID the specified key, allowing access to
 *        the public key via the PSA Crypto API. This must be called once
 *        before the key context can be used.
 *
 * @param ctx      Pointer to the key context.
 * @param key_id   The key ID in the HUK secure service (see km_key_type_t).
 * @param label    Unique, descriptive string describing this key context.
 */
void km_context_init(km_key_context_t *ctx,
		     km_key_type_t key_id,
		     const unsigned char *label)
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

	/* Set the key ID to match the secure service list. */
	ctx->key_id = key_id;

	/* Assign a unique label, within the limits of available memory. */
	if (sizeof(ctx->label) > (strlen(label) + 1)) {
		strcpy(ctx->label, label);
	} else {
		LOG_ERR("Insufficient memory to copy key label");
	}

	/* Request the public key from the secure service. */
	status = al_psa_status(
		psa_huk_get_pubkey(&ctx->key_id,
				   public_key,
				   public_key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export the_public_key");
		goto err;
	} else {
		ctx->status = KEY_GEN;
	}

	/* Display the public key and label for debug purposes. */
	printf("%s public key\n", ctx->label);
	sf_hex_tabulate_16(&fmt, public_key, public_key_len);

err:
	/* Dump any queued log messages, and wait for system events. */
	al_dump_log();
}

km_key_context_t *km_context_get()
{
	static km_key_context_t k_ctx[KEY_COUNT] = { 0 };

	return k_ctx;
}

void km_keys_init(void)
{
	km_key_context_t *ctx = km_context_get();

	/* Populate the TLS client key context. */
	km_context_init(&ctx[KEY_CLIENT_TLS],
			KEY_ID_CLIENT_TLS,
			"Device Client TLS");

	/* Populate the COSE SIGN key context. */
	km_context_init(&ctx[KEY_C_SIGN],
			KEY_ID_C_SIGN,
			"Device COSE SIGN");

	/* Populate the COSE ENCRYPT key context. */
	km_context_init(&ctx[KEY_C_ENCRYPT],
			KEY_ID_C_ENCRYPT,
			"Device COSE ENCRYPT");
}
