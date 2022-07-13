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

/* Template for an ASN.1 encoded EC private key.  See RFC5915. */
static const uint8_t key_template[] = {
	/* SEQUENCE (length) */
	0x30,
	3 + 2 + 32 + 12,
	/* INTEGER 1 (version) */
	0x02, 0x01, 0x01,
	/* OCTET STRING (32 bytes) */
	0x04, 0x20,
	/* Private key, 32 bytes. */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* OID: prime256v1. */
	0xa0, 0x0a,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07,
};
#define PRIVATE_KEY_OFFSET 7
#define PRIVATE_KEY_SIZE 32

int lkey_convert(struct km_key_context *ctx)
{
	psa_status_t res;
	size_t buf_len = 0;

	LOG_DBG("Starting to convert key");

	if (sizeof(key_template) != sizeof(ctx->local_private)) {
		return -EINVAL;
	}
	memcpy(ctx->local_private, key_template, sizeof(key_template));

	res = psa_huk_export_privkey(ctx->key_id, ctx->local_private + PRIVATE_KEY_OFFSET,
				     PRIVATE_KEY_SIZE, &buf_len);
	if (res != PSA_SUCCESS) {
		LOG_ERR("Unable to export: %d", res);
		return -EINVAL;
	}
	if (buf_len != PRIVATE_KEY_SIZE) {
		return -EINVAL;
	}
	ctx->local_private_len = sizeof(key_template);
	LOG_DBG("Export: %d, len %d", res, buf_len);
	return 0;
}
