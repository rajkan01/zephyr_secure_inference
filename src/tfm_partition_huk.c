/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include "tfm_partition_huk.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t psa_huk_get_pubkey(psa_key_id_t *key_id,
				uint8_t *ec_pk_data,
				size_t ec_pk_data_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = key_id, .len = sizeof(psa_key_id_t) },
	};

	psa_outvec out_vec[] = {
		{ .base = ec_pk_data, .len = ec_pk_data_size },
	};

	handle = psa_connect(TFM_HUK_EXPORT_PUBKEY_SID,
			     TFM_HUK_EXPORT_PUBKEY_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  in_vec,
			  IOVEC_LEN(in_vec),
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}

psa_status_t psa_huk_get_uuid(void *uuid,
			      size_t uuid_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = uuid, .len = uuid_size }
	};

	handle = psa_connect(TFM_HUK_GEN_UUID_SID,
			     TFM_HUK_GEN_UUID_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle,
			  PSA_IPC_CALL,
			  NULL,
			  0,
			  out_vec,
			  IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}
