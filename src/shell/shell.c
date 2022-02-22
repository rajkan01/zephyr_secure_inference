/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <ctype.h>
#include <shell/shell.h>
#include "shell/cmd_key_mgmt.h"

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

static int
psa_shell_invalid_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: invalid argument \"%s\"\n", arg_name);

	return -EINVAL;
}

static int
psa_shell_cmd_version(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "%s", "1.0.0");

	return 0;
}

static int
psa_shell_get_uuid(const struct shell *shell, size_t argc, char **argv)
{
	unsigned char uuid[37];
	psa_status_t status;

	status = psa_get_uuid(uuid, sizeof(uuid));
	if (status != 0) {
		return -EINVAL;
	}
	shell_print(shell, "%s", uuid);
	return 0;
}

static int
psa_shell_get_key_sts(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Keys", "Key ID", "Status" };
	char *k_sts[] = { "X.509 certificate gen", "Key generated", "Unknown" };
	key_context_t *ctx = get_key_context();

	shell_print(shell, "|   %-20s|  %-12s |  %-22s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < 3; i++) {
		shell_print(shell, "|   %-20s|  0x%-10x |  %-22s |", ctx[i].label,
			    ctx[i].key_id, k_sts[ctx[i].status]);
	}

	return 0;
}

static int
psa_shell_get_pubkey(const struct shell *shell, size_t argc, char **argv)
{

	uint8_t public_key[65] = { 0 }; /* EC public key = 65 bytes. */
	size_t public_key_len = sizeof(public_key);
	uint8_t key_idx_start = 0, key_idx_end = 3;
	_Bool valid_key_id = false;
	psa_status_t status;
	key_context_t *ctx = get_key_context();

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

		status = psa_get_pubkey(public_key, public_key_len,
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

/* Subcommand array for "info" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_info,
    /* 'version' command handler. */
	SHELL_CMD(version, NULL, "app version", psa_shell_cmd_version),
	/* 'UUID' command handler. */
	SHELL_CMD(uuid, NULL, "Device uuid", psa_shell_get_uuid),
    /* Array terminator. */
	SHELL_SUBCMD_SET_END
);

/* Subcommand array for "keys" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_keys,
    /* 'Status' command handler. */
	SHELL_CMD(status, NULL, "Device keys status", psa_shell_get_key_sts),
    /* 'Public key' command handler. */
	SHELL_CMD(public, NULL, "List public key(s) and key IDs",
		psa_shell_get_pubkey),
    /* Array terminator. */
	SHELL_SUBCMD_SET_END
);

/* Root command "info" (level 0). */
SHELL_CMD_REGISTER(info, &sub_cmd_info, "Device information", NULL);
/* Root command "keys" (level 0). */
SHELL_CMD_REGISTER(keys, &sub_cmd_keys, "Key Management", NULL);
#endif  /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
