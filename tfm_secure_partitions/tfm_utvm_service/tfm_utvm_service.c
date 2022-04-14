/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_utvm_service.h"
#include "psa/crypto.h"
#include "tfm_sp_log.h"
#include "tfm_plat_test.h"
#include "target_cfg.h"
#include "tfm_huk_deriv_srv_api.h"
#include "platform_regs.h"
#include "tvmgen_default.h"
#include "utvm_platform.h"

#define SERV_NAME "UTVM SERVICE"

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

/* The model index is key to finding the utvm model from the utvm_models array
 * and this gets validated in the utvm secure service to select the model to
 * run the inference engine.
 */
typedef enum {
	UTVM_MODEL_SINE = 0,                    /**< Sine inference model index*/
	UTVM_MODEL_COUNT,                       /**< Number of models present */
} utvm_model_idx_t;

/* List of supported utvm models */
const char *utvm_models[UTVM_MODEL_COUNT] = { "UTVM_MODEL_SINE" };

typedef struct {
	huk_enc_format_t enc_format;
	char model[32];
} utvm_config_t;

/**
 * \brief Run inference using UTVM
 */
psa_status_t tfm_utvm_infer_run(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	float model_in_val, model_out_val;
	uint8_t inf_val_encoded_buf[msg->out_size[0]];
	_Bool is_model_supported = false;
	size_t inf_val_encoded_buf_len = 0;
	utvm_config_t cfg;

	/* Check size of invec/outvec parameter */
	if (msg->in_size[1] != sizeof(utvm_config_t)) {
		status = PSA_ERROR_PROGRAMMER_ERROR;
		goto err;
	}

	utvm_stack_mgr_init();
	psa_read(msg->handle, 0, &model_in_val, msg->in_size[0]);
	psa_read(msg->handle, 1, &cfg, sizeof(utvm_config_t));

	for (int i = 0; i < UTVM_MODEL_COUNT; i++) {
		if (strcmp(utvm_models[i], cfg.model) == 0) {
			is_model_supported = true;
			break;
		}
	}

	if (!is_model_supported) {
		log_err_print("%s model is not supported", cfg.model);
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}

	struct tvmgen_default_inputs inputs = {
		.dense_4_input = (void *)&model_in_val,
	};
	struct tvmgen_default_outputs outputs = {
		.Identity = (void *)&model_out_val,
	};

	/* Run inference */
	log_info_print("Starting secure inferencing");
	status = tvmgen_default_run(&inputs, &outputs);
	if (status != 0) {
		log_err_print("failed with %d", status);
		goto err;
	}

	log_info_print("Starting CBOR/COSE encoding");
	status = psa_huk_cose_sign(&model_out_val,
				   cfg.enc_format,
				   inf_val_encoded_buf,
				   msg->out_size[0],
				   &inf_val_encoded_buf_len);
	if (status != PSA_SUCCESS) {
		log_err_print("failed with %d", status);
		goto err;
	}

	psa_write(msg->handle,
		  0,
		  inf_val_encoded_buf,
		  inf_val_encoded_buf_len);
	psa_write(msg->handle,
		  1,
		  &inf_val_encoded_buf_len,
		  sizeof(inf_val_encoded_buf_len));

err:
	return status;
}

void tfm_utvm_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	/* Retrieve the message corresponding to the UTVM service signal */
	status = psa_get(TFM_UTVM_SINE_MODEL_SERVICE_SIGNAL, &msg);
	if (status != PSA_SUCCESS) {
		return;
	}

	/* Decode the message */
	switch (msg.type) {
	/* Any setup or teardown on IPC connect or disconnect goes here. If
	 * nothing then just reply with success.
	 */
	case PSA_IPC_CONNECT:
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;

	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	default:
		psa_panic();
	}
}

/**
 * \brief Generate EC key.
 */
static void  tfm_utvm_gen_ec_key(const uint8_t  *hpke_info,
				 size_t hpke_info_len,
				 psa_key_id_t ec_key_id,
				 psa_key_usage_t key_usage_flag)
{
	psa_status_t status;

	status = psa_huk_deriv_ec_key(&ec_key_id,
				      hpke_info,
				      hpke_info_len,
				      &key_usage_flag);

	if (status != PSA_SUCCESS) {
		log_err_print("failed with status %d", status);
		goto err;
	}

	return status;
err:
	psa_panic();
}

/**
 * \brief EC keys init function generates three unique EC keys using HUK
 * derivation secure service.
 */
void tfm_utvm_ec_keys_init()
{
	static _Bool is_ec_keys_init_done = false;

	if (!is_ec_keys_init_done) {
		/** These are the hpke_info passed to key derivation for generating
		 *  three unique keys - Device client TLS, Device COSE SIGN, Device
		 *  COSE encryption.
		 */
		const char *hpke_info[3] = {
			"HUK_CLIENT_TLS1",
			"HUK_COSE_SIGN1",
			"HUK_COSE_ENCRYPT1"
		};

		tfm_utvm_gen_ec_key((const uint8_t *)hpke_info[0],
				    strlen(hpke_info[0]),
				    HUK_CLIENT_TLS,
				    (PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE));
		tfm_utvm_gen_ec_key((const uint8_t *)hpke_info[1],
				    strlen(hpke_info[1]),
				    HUK_COSE_SIGN,
				    (PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH));
		tfm_utvm_gen_ec_key((const uint8_t *)hpke_info[2],
				    strlen(hpke_info[2]),
				    HUK_COSE_ENCRYPT,
				    PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_ENCRYPT);
		is_ec_keys_init_done = true;
	}
}

/**
 * \brief The UTVM service partition's entry function.
 */
void tfm_utvm_service_req_mngr_init(void)
{
	psa_signal_t signals;

	/* Ec keys init */
	tfm_utvm_ec_keys_init();
	log_info_print("UTVM initalisation completed");

	/* Continually wait for one or more of the partition's RoT Service or
	 * interrupt signals to be asserted and then handle the asserted signal(s).
	 */
	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		if (signals & TFM_UTVM_SINE_MODEL_SERVICE_SIGNAL) {
			tfm_utvm_signal_handle(
				TFM_UTVM_SINE_MODEL_SERVICE_SIGNAL,
				tfm_utvm_infer_run);
		} else {
			psa_panic();
		}
	}
}
