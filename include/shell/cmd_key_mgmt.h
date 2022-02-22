/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_sp_inf/tfm_sip_srv_api.h"
#include "util/util_app_log.h"
#include "cose/cose_verify.h"

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

psa_status_t psa_get_uuid(unsigned char *uuid, size_t uuid_size);
psa_status_t psa_get_pubkey(uint8_t *public_key, size_t public_key_len, key_context_t ctx);
#endif
