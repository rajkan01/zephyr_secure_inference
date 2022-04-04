/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h> /*stroutl */
#include <shell_common.h>
#include <logging/log.h>

#include "tfm_partition_huk.h"
#include "key_mgmt.h"
#include "x509_csr_gen.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

static int
cmd_keys_key_stat(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Key", "Key ID", "Status" };
	char *k_sts[] = { "unknown", "Key generated", "X.509 certificate gen" };
	km_key_context_t *ctx = km_get_context();

	shell_print(shell, "| %-20s| %-12s | %-22s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < KEY_COUNT; i++) {
		shell_print(shell, "| %-20s| 0x%-10x | %-22s |", ctx[i].label,
			    ctx[i].key_id, k_sts[ctx[i].status]);
	}

	return 0;
}

/* Validate the Key ID and get the key context index */
static _Bool cmd_keys_get_key_idx(uint32_t key_id, uint8_t *key_idx)
{
	km_key_context_t *ctx = km_get_context();

	for (int i = 0; i < KEY_COUNT; i++) {
		if (ctx[i].key_id == key_id) {
			*key_idx = i;
			return true;
		}
	}
	return false;
}

static int
cmd_keys_pubkey(const struct shell *shell, size_t argc, char **argv)
{
	unsigned char public_key[512] = { 0 };
	size_t public_key_len = 0;
	uint8_t key_idx_start = 0, key_idx_end = KEY_COUNT;
	psa_status_t status;
	km_key_context_t *ctx = km_get_context();

	if ((argc == 2) && (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Display public key(s) in PEM format\n");
		shell_print(shell, "  $ %s %s <Key ID>\n", argv[-1], argv[0]);
		shell_print(shell,
			    "  [Key ID]   Optional: Key ID ('status' for list)\n");
		shell_print(shell, "Example: $ %s %s", argv[-1], argv[0]);
		shell_print(shell,
			    "         $ %s %s 5001 (List public key of 5001 key ID)",
			    argv[-1], argv[0]);
		return 0;
	}

	/* Too many arguments. */
	if (argc > 2) {
		return shell_com_too_many_arg(shell, argv[2]);
	}

	if (argc > 1) {
		uint32_t rx_key_id = strtoul(argv[1], NULL, 16);
		if (cmd_keys_get_key_idx(rx_key_id, &key_idx_start)) {
			key_idx_end = key_idx_start + 1;
		} else {
			return shell_com_invalid_arg(shell, argv[1]);
		}
	}

	while (key_idx_start < key_idx_end) {
		public_key_len = 0;
		status = km_enc_pubkey_pem(key_idx_start,
					   public_key,
					   sizeof(public_key),
					   &public_key_len);

		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to get the public key",
						 status);
		}

		shell_print(shell, "Key ID: 0x%x", ctx[key_idx_start].key_id);
		shell_print(shell, "%s Public key:", ctx[key_idx_start].label);
		shell_print(shell, "%s", public_key);
		key_idx_start++;
	}

	return 0;
}

static int
cmd_keys_csr(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t key_idx = 0;
	char *csr_supported_format[] = { "PEM", "JSON", "PEM_JSON", "Unknown" };
	x509_csr_fmt_t csr_fmt = CSR_NONE;
	_Bool is_valid_csr_format = false;
	psa_status_t status;

	if ((argc == 1) || (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Generate a CSR for the given key id and format\n");
		shell_print(shell, "  $ %s %s <Format> <Key ID>\n",
			    argv[-1], argv[0]);
		shell_print(shell, "  <Format>   'PEM', 'JSON', 'PEM_JSON'");
		shell_print(shell, "  <Key ID>   Run 'status' for key ID list\n");
		shell_print(shell, "Example: $ %s %s PEM 5001", argv[-1], argv[0]);
		return 0;
	}

	/* Missing argument. */
	if (argc == 2) {
		return shell_com_missing_arg(shell, "Key ID");
	}

	/* Too many arguments. */
	if (argc > 3) {
		return shell_com_too_many_arg(shell, argv[3]);
	}

	/* Validate the display format */
	for (int i = 0; i < CSR_NONE; i++) {
		if (strcmp(argv[1], csr_supported_format[i]) == 0) {
			csr_fmt = i;
			is_valid_csr_format = true;
			break;
		}
	}

	if (!is_valid_csr_format) {
		return shell_com_invalid_arg(shell, argv[1]);
	}

	uint32_t rx_key_id = strtoul(argv[2], NULL, 16);

	/* Parse valid request. */
	if (!cmd_keys_get_key_idx(rx_key_id, &key_idx)) {
		return shell_com_invalid_arg(shell, argv[2]);
	}

	static unsigned char csr[1024];
	unsigned char uuid[37];

	/* Get the UUID */
	status = al_psa_status(km_get_uuid(uuid, sizeof(uuid)), __func__);
	if (status != PSA_SUCCESS) {
		return shell_com_rc_code(shell,
					 "Unable to read UUID",
					 status);
	}

	/* Generate CSR PEM format using Mbed TLS */
	status = x509_csr_generate(key_idx,
				   csr,
				   sizeof(csr),
				   uuid,
				   sizeof(uuid));
	if (status != PSA_SUCCESS) {
		return shell_com_rc_code(shell,
					 "Failed to generate CSR",
					 status);
	}
	if (csr_fmt == CSR_PEM_FORMAT || csr_fmt == CSR_PEM_JSON_FORMAT) {
		shell_print(shell, "%s", csr);
	}
	if (csr_fmt == CSR_JSON_FORMAT || csr_fmt == CSR_PEM_JSON_FORMAT) {
		static unsigned char csr_json[1024] = { 0 };

		/* CSR encode to JSON format */
		status = x509_csr_json_encode(csr,
					      csr_json,
					      sizeof(csr_json));
		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to encode CSR",
						 status);
		}
		shell_print(shell, "%s", csr_json);
	}

	return 0;
}

/* Subcommand array for "keys" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_keys,
	/* 'Status' command handler. */
	SHELL_CMD(status, NULL, "Device keys status", cmd_keys_key_stat),
	/* 'Public key' command handler. */
	SHELL_CMD(public, NULL, "List public key(s) and key IDs", cmd_keys_pubkey),
    /* 'CSR' command handler. */
	SHELL_CMD(csr, NULL, "Generate and display CSR on given key ID", cmd_keys_csr),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Root command "keys" (level 0). */
SHELL_CMD_REGISTER(keys, &sub_cmd_keys, "Key Management", NULL);

#endif
