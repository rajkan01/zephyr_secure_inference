/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/client.h"
#include "tfm_sip_srv_api.h"

// psa_status_t example_read_lsm303(uint8_t *data,
//                               size_t data_size)
// {
//      psa_status_t status;
//      psa_handle_t handle;
//
//      psa_outvec out_vec[] = {
//              { .base = data, .len = data_size },
//      };
//
//      handle = psa_connect(TFM_EXAMPLE_READ_LSM303_SID, TFM_EXAMPLE_READ_LSM303_VERSION);
//      if (!PSA_HANDLE_IS_VALID(handle)) {
//              return PSA_HANDLE_TO_ERROR(handle);
//      }
//
//      status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1);
//
//      psa_close(handle);
//
//      return status;
// }

psa_status_t psa_si_tflm_hello(psa_key_id_t *key_id,
			       const float *input,
			       size_t input_length,
			       uint8_t *encoded_buf,
			       size_t encoded_buf_size,
			       size_t *encoded_buf_len)
{
	psa_status_t status;
	psa_handle_t handle;
	psa_invec in_vec[] = {
		{ .base = key_id, .len = sizeof(psa_key_id_t) },
		{ .base = input, .len = input_length },
	};

	psa_outvec out_vec[] = {
		{ .base = encoded_buf, .len = encoded_buf_size },
		{ .base = encoded_buf_len, .len = sizeof(size_t) },
	};

	handle = psa_connect(TFM_TFLM_SERVICE_HELLO_SID,
			     TFM_TFLM_SERVICE_HELLO_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_HANDLE_TO_ERROR(handle);
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
