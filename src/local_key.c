/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
#include <key_mgmt.h>
#include <tfm_partition_huk.h>
#include <local_key.h>

LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/**
 * @file Local key management.
 *
 * The most secure management of private keys is to have them contained within
 * the secure side, and only reference them through the API.  However, there are
 * situations where this is not practical, where the key has to be used by some
 * other crypto system. At the time of writing, this is also necessary to
 * support TLS with a private certificate, as it isn't possible to build both
 * TF-M and Mbed TLS with the PSA API enabled.
 *
 * To support this, this module supports the derivation of a private key that is
 * used on the non-secure side.  The key is a valid key, for ECDSA P-256, and
 * can be loaded into the secure side, but is also accessible on the non-secure
 * side.
 */

int lkey_convert(struct km_key_context *ctx)
{
	psa_status_t res;
	size_t buf_len = 0;

	LOG_INF("Starting to convert key");

	/* Let's see if we can just export it. */
	res = psa_huk_export_privkey(ctx->key_id, ctx->local_private, sizeof(ctx->local_private),
				     &buf_len);
	if (res != PSA_SUCCESS) {
		LOG_ERR("Unable to export: %d", res);
		return -EINVAL;
	}
	LOG_INF("Export: %d, len %d", res, buf_len);
	return 0;
}
