/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h> /*stroutl */
#include <shell/shell.h>
#include <logging/log.h>

#include "tfm_partition_huk.h"
#include "key_mgmt.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

static int
cmd_keys_key_stat(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Key", "Key ID", "Status" };
	char *k_sts[] = { "X.509 certificate gen", "Key generated", "Unknown" };
	km_key_context_t *ctx = km_context_get();

	shell_print(shell, "| %-20s| %-12s | %-22s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < KEY_COUNT; i++) {
		shell_print(shell, "| %-20s| 0x%-10x | %-22s |", ctx[i].label,
			    ctx[i].key_id, k_sts[ctx[i].status]);
	}

	return 0;
}

static int
cmd_keys_pubkey(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t public_key[KM_PUBLIC_KEY_SIZE] = { 0 };
	size_t public_key_len = sizeof(public_key);
	uint8_t key_idx_start = 0, key_idx_end = KEY_COUNT;
	_Bool valid_key_id = false;
	psa_status_t status;
	km_key_context_t *ctx = km_context_get();

	if (argc > 1) {
		uint32_t rx_key_id = strtoul(argv[1], NULL, 16);
		while (key_idx_start < key_idx_end) {
			if (ctx[key_idx_start].key_id == rx_key_id) {
				valid_key_id = true;
				break;
			}
			key_idx_start++;
		}
		if (valid_key_id) {
			key_idx_end = key_idx_start + 1;
		} else {
			goto err;
		}
	}

	while (key_idx_start < key_idx_end) {

		status = km_get_pubkey(public_key, public_key_len,
					ctx[key_idx_start]);
		if (status != 0) {
			shell_print(shell, "Error: Failed to get the public key");
			return -EINVAL;
		}
		shell_print(shell, "Key label: %s", ctx[key_idx_start].label);
		shell_print(shell, "Key id: 0x%x", ctx[key_idx_start].key_id);
		shell_print(shell, "Public key:");
		for (int i = 0; i < public_key_len; i++) {
			if (i > 0 && !(i % 16)) {
				shell_print(shell, "");
			}

			shell_fprintf(shell, SHELL_NORMAL, "%02x ",
				      public_key[i] & 0xFF);
		}
		shell_print(shell, "\n");
		key_idx_start++;
	}

	return 0;
err:
	shell_print(shell, "Error: invalid key id argument \"%s\"\n", argv[1]);
	return -EINVAL;
}

/* Subcommand array for "keys" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_keys,
	/* 'Status' command handler. */
	SHELL_CMD(status, NULL, "Device keys status", cmd_keys_key_stat),
	/* 'Public key' command handler. */
	SHELL_CMD(public, NULL, "List public key(s) and key IDs", cmd_keys_pubkey),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Root command "keys" (level 0). */
SHELL_CMD_REGISTER(keys, &sub_cmd_keys, "Key Management", NULL);

#endif
