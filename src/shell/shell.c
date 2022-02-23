/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <ctype.h>
#include <shell/shell.h>
#include "shell/cmd_key_mgmt.h"
#include "shell/cmd_infer.h"
#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include <stdlib.h>

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

static int
psa_shell_list_infer_model(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Model label", "Model ID", "Status" };
	char *m_sts[] = { "Not Active", "Active", "Unknown" };
	infer_model_ctx_t *ctx = get_infer_model_context();

	shell_print(shell, "|   %-15s|  %-12s |  %-8s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < ctx->model_count; i++) {
		shell_print(shell, "|   %-15s|  0x%-10x |  %-8s |",
			    ctx->model_info[i].
			    sid_label, ctx->model_info[i].sid,
			    m_sts[ctx->model_info[i].sts]);
	}

	return 0;
}
static int
psa_shell_get_infer(const struct shell *shell, size_t argc, char **argv)
{
	psa_status_t status;
	const float PI = 3.14159265359f;
	float deg = PI / 180.0;
	float usr_in_val_start = 0,
	      usr_in_val_end = 0,
		  stride = 1.0,
	      model_out_val;
	uint8_t key_ctx_idx = 1;        // C_SIGN key context stored index loaction
	uint8_t pubkey[65] = { 0 };     /* EC public key = 65 bytes. */
	size_t pubkey_len = sizeof(pubkey);
	uint8_t infval_enc_buf[256];
	size_t infval_enc_buf_len = 0;
	key_context_t *ctx = get_key_context();
	infer_model_ctx_t *m_ctx = get_infer_model_context();
	_Bool is_valid_model = false;

	if (argc > 2) {
		for (int i = 0; i < m_ctx->model_count; i++) {
			if (strcmp(argv[1], m_ctx->model_info[i].sid_label) == 0) {
				shell_print(shell, "Model label:  %s", argv[1]);
				is_valid_model = true;
			}
		}
		if (!is_valid_model) {
			shell_print(shell, "Invalid inference model");
			return -EINVAL;
		}
		usr_in_val_start = strtof(argv[2], NULL);
		if (argc > 3) {
			usr_in_val_end = strtof(argv[3], NULL);
		} else {
			usr_in_val_end = usr_in_val_start;
		}
		if (argc > 4) {
			stride = strtof(argv[4], NULL);
		}
		shell_print(shell, "Start: %.2f End: %.2f stride: %.2f\n", usr_in_val_start, usr_in_val_end, stride);
	} else {
		shell_print(shell, "Expected minimum 'infer get' command arguments '<Model label> <Value>'");
		return -EINVAL;
	}

	while (usr_in_val_start <= usr_in_val_end) {
		status =  psa_get_infer(ctx[key_ctx_idx].key_id,
					(usr_in_val_start * deg),
					&infval_enc_buf[0],
					sizeof(infval_enc_buf),
					&infval_enc_buf_len);

		if (status != 0) {
			return -EINVAL;
		} else {
			shell_print(shell, "\nCBOR encoded and COSE signed inference value:");
			shell_hexdump(shell, infval_enc_buf, infval_enc_buf_len);
			shell_print(shell, "\n");
		}
		status = psa_get_pubkey(pubkey, pubkey_len,
					ctx[key_ctx_idx]);

		if (status != 0) {
			shell_print(shell, "Failed to get the public key");
			return -EINVAL;
		}
		status = psa_verify_sign(infval_enc_buf,
					 infval_enc_buf_len,
					 pubkey,
					 pubkey_len,
					 &model_out_val);
		if (status != 0) {
			return -EINVAL;
		} else {
			shell_print(shell, "NS: Verified the signature using the public key.");
		}

		shell_print(shell, "Model: Sine of %.2f deg is: %f\t", usr_in_val_start,
			    model_out_val);
		shell_print(shell, "C Mathlib: Sine of %.2f deg is: %f\t",
			    usr_in_val_start, sin(usr_in_val_start * deg));
		shell_print(shell, "Deviation: %f\n",
			    fabs(sin(usr_in_val_start) - model_out_val));
		usr_in_val_start += stride;
	}
	return 0;
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

/* Subcommand array for "infer" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_infer,
    /* 'Model' command handler. */
	SHELL_CMD(model, NULL, "List model labels and its IDs",
		psa_shell_list_infer_model),
    /* 'get' command handler. */
	SHELL_CMD(get, NULL, "Run inference for a given input value(s) ",
		psa_shell_get_infer),
    /* Array terminator. */
	SHELL_SUBCMD_SET_END
);

/* Root command "info" (level 0). */
SHELL_CMD_REGISTER(info, &sub_cmd_info, "Device information", NULL);
/* Root command "keys" (level 0). */
SHELL_CMD_REGISTER(keys, &sub_cmd_keys, "Key Management", NULL);
/* Root command "infer" (level 0). */
SHELL_CMD_REGISTER(infer, &sub_cmd_infer, "Inference Engine", NULL);
#endif  /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
