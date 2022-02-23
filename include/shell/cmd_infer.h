/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "util/util_app_log.h"
#include "cose/cose_verify.h"
#include "pk/pk_import_verify_sign.h"
#include "util/util_app_log.h"
#include "util/util_sformat.h"
#include <math.h>

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

psa_status_t psa_get_infer(psa_key_id_t key_id,
			   float input,
			   uint8_t *infval_enc_buf,
			   size_t inf_val_enc_buf_size,
			   size_t *infval_enc_buf_len);

psa_status_t psa_verify_sign(uint8_t *infval_enc_buf,
			     size_t infval_enc_buf_len,
			     uint8_t *pubkey,
			     size_t pubkey_len,
			     float *out_val);
#endif
