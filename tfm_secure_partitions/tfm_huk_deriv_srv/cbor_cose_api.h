/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CBOR_COSE_API_H__
#define __CBOR_COSE_API_H__

#include <stdint.h>
#include "psa/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief CBOR encode and sign the encoded inference value using private key of
 * the given key handle.
 *
 * \param[in]   key_handle                Key handle.
 * \param[in]   inf_val                   The inference input value.
 * \param[out]  inf_val_encoded_buf       Buffer to which encoded data *
 *                                        is written into.
 * \param[in]   inf_val_encoded_buf_size  Size of inf_val_encoded_buf in bytes.
 * \param[out]  inf_val_encoded_buf_len   Encoded and signed payload len in
 *                                        bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cose_encode_sign(psa_key_handle_t key_handle,
				  float inf_val,
				  uint8_t *inf_val_encoded_buf,
				  size_t inf_val_encoded_buf_size,
				  size_t *inf_val_encoded_buf_len);

/**
 * \brief Encoding the inference value in CBOR format.
 *
 * \param[in]   inf_val                   The inference input value.
 * \param[out]  inf_val_encoded_buf       Buffer to which encoded data
 *                                        is written into.
 * \param[in]   inf_val_encoded_buf_size  Size of inf_val_encoded_buf in bytes.
 * \param[out]  inf_val_encoded_buf_len   Encoded and signed payload len in
 *                                        bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_cbor_encode(float inf_val,
			     uint8_t *inf_val_encoded_buf,
			     size_t inf_val_encoded_buf_size,
			     size_t *inf_val_encoded_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* __CBOR_COSE_API_H__ */
