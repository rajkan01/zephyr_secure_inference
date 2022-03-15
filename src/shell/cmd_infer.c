/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <math.h>
#include <stdlib.h>
#include <shell/shell.h>
#include <logging/log.h>

#include "cose/cose_verify.h"
#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "infer_mgmt.h"
#include "tfm_partition_huk.h"
#include "tfm_partition_tflm.h"
#include "util_app_log.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

// static int
// invalid_arg(const struct shell *shell, char *arg_name)
// {
// 	shell_print(shell, "Error: invalid argument \"%s\"\n", arg_name);
//
// 	return -EINVAL;
// }

static int
cmd_infer_list_models(const struct shell *shell, size_t argc, char **argv)
{
	char *row1[] = { "Model Label", "Model ID", "Status" };
	char *m_sts[] = { "Not Active", "Active", "Unknown" };
	infer_ctx_t *ctx = infer_context_get();

	shell_print(shell, "| %-15s| %-12s | %-8s |", row1[0], row1[1],
		    row1[2]);
	for (int i = 0; i < INFER_MODEL_COUNT; i++) {
		shell_print(shell, "| %-15s| 0x%-10x | %-8s |",
			    ctx[i].sid_label,
			    ctx[i].sid,
			    m_sts[ctx[i].sts]);
	}

	return 0;
}
static int
cmd_infer_get_val(const struct shell *shell, size_t argc, char **argv)
{
	psa_status_t status;
	const float PI = 3.14159265359f;
	float deg = PI / 180.0;
	float usr_in_val_start = 0,
	      usr_in_val_end = 0,
	      stride = 1.0,
	      model_out_val;
	uint8_t key_ctx_idx = KEY_C_SIGN;
	uint8_t pubkey[KM_PUBLIC_KEY_SIZE] = { 0 };
	size_t pubkey_len = sizeof(pubkey);
	static uint8_t infval_enc_buf[256];
	size_t infval_enc_buf_len = 0;
	infer_ctx_t *m_ctx = infer_context_get();
	_Bool is_valid_model = false;

	if (argc > 2) {
		for (int i = 0; i < INFER_MODEL_COUNT; i++) {
			if (strcmp(argv[1], m_ctx[i].sid_label) == 0) {
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
		status =  infer_get_cose_output(key_ctx_idx,
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
		status = km_get_pubkey(pubkey, pubkey_len,
				       key_ctx_idx);

		if (status != 0) {
			shell_print(shell, "Failed to get the public key");
			return -EINVAL;
		}
		status = infer_verify_signature(infval_enc_buf,
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

/* Subcommand array for "infer" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_infer,
	/* 'model' command handler. */
	SHELL_CMD(model, NULL, "List available models", cmd_infer_list_models),
	/* 'get' command handler. */
	SHELL_CMD(get, NULL, "Run inference on given input(s)", cmd_infer_get_val),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Root command "infer" (level 0). */
SHELL_CMD_REGISTER(infer, &sub_cmd_infer, "Inference engine", NULL);

#endif /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
