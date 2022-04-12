/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <math.h>
#include <logging/log.h>

#include "shell_common.h"
#include "cose/cose_verify.h"
#include "cose/mbedtls_ecdsa_verify_sign.h"
#include "infer_mgmt.h"
#include "tfm_partition_huk.h"
#include "tfm_partition_tflm.h"
#include "util_app_log.h"

#define SINE_INPUT_MIN 0
#define SINE_INPUT_MAX 359

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

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
cmd_infer_get_sine_val(const struct shell *shell,
		       size_t argc,
		       char **argv,
		       infer_get_cose_output cose_output,
		       const char *model)
{
	psa_status_t status;
	const float PI = 3.14159265359f;
	float deg = PI / 180.0;
	float usr_in_val_start = 0,
	      usr_in_val_end = 0,
	      stride = 1.0,
	      model_out_val,
	      usr_in_val_deg;
	uint8_t key_ctx_idx = KEY_C_SIGN;
	uint8_t pubkey[KM_PUBLIC_KEY_SIZE] = { 0 };
	size_t pubkey_len = sizeof(pubkey);
	static uint8_t infval_enc_buf[256];
	size_t infval_enc_buf_len = 0;

	if ((argc == 1) || (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Requests a new sine wave approximation using TFLM.\n");
		shell_print(shell, "  $ %s %s %s <start> <[stop] [stride]>\n",
			    argv[-2], argv[-1], argv[0]);
		shell_print(shell,
			    "  <start>    Initial inference valid input 0 to 359");
		shell_print(shell,
			    "  [stop]     Optional: Final inference valid input 0 to 359");
		shell_print(shell,
			    "  [stride]   Optional: Stride between start and stop\n");
		shell_print(shell,
			    "Example: $ %s %s %s 1.5", argv[-2], argv[-1], argv[0]);
		shell_print(shell,
			    "         $ %s %s %s 1.0 2.0 0.25",
			    argv[-2], argv[-1], argv[0]);
		return 0;
	}

	if (!shell_com_str_to_float_min_max(argv[1],
					    &usr_in_val_start,
					    SINE_INPUT_MIN,
					    SINE_INPUT_MAX)) {
		return shell_com_invalid_arg(shell, argv[1]);
	}

	if (argc > 2) {
		if (!shell_com_str_to_float_min_max(argv[2],
						    &usr_in_val_end,
						    SINE_INPUT_MIN,
						    SINE_INPUT_MAX)) {
			return shell_com_invalid_arg(shell, argv[2]);
		}

		if (usr_in_val_start > usr_in_val_end) {
			return shell_com_invalid_arg(shell,
						     "Invalid start value (start > stop)");
		}
	} else {
		usr_in_val_end = usr_in_val_start;
	}

	if (argc > 3) {
		if (!shell_com_str_to_float_min_max(argv[3],
						    &stride,
						    SINE_INPUT_MIN,
						    SINE_INPUT_MAX) || stride == 0) {
			return shell_com_invalid_arg(shell, argv[3]);
		}

		if ((usr_in_val_start + stride) > usr_in_val_end) {
			return shell_com_invalid_arg(shell,
						     "Out of boundary ((start + stride) > stop)");
		}
	}

	shell_print(shell,
		    "Start: %.2f End: %.2f stride: %.2f",
		    usr_in_val_start, usr_in_val_end, stride);

	while (usr_in_val_start <= usr_in_val_end) {
		usr_in_val_deg = usr_in_val_start * deg;
		status =  cose_output(
			INFER_ENC_COSE_SIGN1,
			model,
			(void *)&usr_in_val_deg,
			sizeof(usr_in_val_deg),
			&infval_enc_buf[0],
			sizeof(infval_enc_buf),
			&infval_enc_buf_len);

		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to get COSE encoded inference output",
						 status);
		} else {
			shell_print(shell, "CBOR encoded and COSE signed inference value:");
			shell_hexdump(shell, infval_enc_buf, infval_enc_buf_len);
		}
		status = km_get_pubkey(pubkey, pubkey_len,
				       key_ctx_idx);

		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to get the public key",
						 status);
		}
		status = infer_verify_signature(infval_enc_buf,
						infval_enc_buf_len,
						pubkey,
						pubkey_len,
						&model_out_val);
		if (status != 0) {
			return shell_com_rc_code(shell,
						 "Failed to verify the signature",
						 status);
		} else {
			shell_print(shell,
				    "Verified the signature using the public key.");
		}

		shell_print(shell, "Model: Sine of %.2f deg is: %f\t",
			    usr_in_val_start, model_out_val);
		shell_print(shell, "C Mathlib: Sine of %.2f deg is: %f\t",
			    usr_in_val_start, sin(usr_in_val_start * deg));
		shell_print(shell, "Deviation: %f\n",
			    fabs(sin(usr_in_val_start) - model_out_val));
		usr_in_val_start += stride;
	}
	return 0;
}

static int
cmd_infer_get_tflm_sine_val(const struct shell *shell,
			    size_t argc,
			    char **argv)
{
	return
		cmd_infer_get_sine_val(shell,
				       argc,
				       argv,
				       infer_get_tflm_cose_output,
				       "TFLM_MODEL_SINE");
}

static int
cmd_infer_get_utvm_sine_val(const struct shell *shell,
			    size_t argc,
			    char **argv)
{
	return
		cmd_infer_get_sine_val(shell,
				       argc,
				       argv,
				       infer_get_utvm_cose_output,
				       "UTVM_MODEL_SINE");
}

static int
cmd_infer_get(const struct shell *shell, size_t argc, char **argv)
{
	infer_ctx_t *m_ctx = infer_context_get();

	if ((argc == 1) || (strcmp(argv[1], "help") == 0)) {
		shell_print(shell, "Requests an inference output from the specified model.\n");
		shell_print(shell, "  $ %s %s <model> ...\n",
			    argv[-1], argv[0]);
		shell_print(shell, "  <model>    Model name\n");
		shell_print(shell, "Models available:");
		for (int i = 0; i < INFER_MODEL_COUNT; i++) {
			shell_print(shell, "  -%s", m_ctx[i].sid_label);
		}
	} else {
		return shell_com_invalid_arg(shell, argv[1]);
	}

	return 0;
}

/* Subcommand array for "model" (level 2). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_model,
	/* 'tflm_sine' command handler. */
	SHELL_CMD_ARG(tflm_sine, NULL, "$ infer get tflm_sine start <[stop] [stride]>", cmd_infer_get_tflm_sine_val, 1, 3),
	/* 'utvm_sine' command handler. */
	SHELL_CMD_ARG(utvm_sine, NULL, "$ infer get utvm_sine start <[stop] [stride]>", cmd_infer_get_utvm_sine_val, 1, 3),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Subcommand array for "infer" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_infer,
	/* 'model' command handler. */
	SHELL_CMD_ARG(model, NULL, "$ infer model", cmd_infer_list_models, 1, 0),
	/* 'get' command handler. */
	SHELL_CMD(get, &sub_cmd_model, "Run inference on given input(s)", cmd_infer_get),
	/* Array terminator. */
	SHELL_SUBCMD_SET_END
	);

/* Root command "infer" (level 0). */
SHELL_CMD_REGISTER(infer, &sub_cmd_infer, "Inference engine", NULL);

#endif /* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
