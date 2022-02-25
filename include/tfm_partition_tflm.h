/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __TFM_PARTITION_TFLM_H__
#define __TFM_PARTITION_TFLM_H__

#include "tfm_api.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// /**
//  * \brief Read magnetometer (LSM303) data.
//  *
//  * \param[out]  data            Buffer to which magnetometer data is
//  *                              written into
//  * \param[out]   data_size      Size of magnetometer data in bytes
//  *
//  * \return Returns error code as specified in \ref psa_status_t
//  */
// psa_status_t example_read_lsm303(uint8_t *data,
//                                 size_t data_size);

/**
 * \brief Run secure inference to manipulate the sine value of input and
 *        encode and sign sine value using COSE CBOR
 *
 * \param[in]   key_id              EC key id which is used to access EC key
 *                                  to sign the payload after inference run
 * \param[in]   input               Angle in degrees
 * \param[out]  encoded_buf         Buffer to which encoded data
 *                                  is written into
 * \param[in]   encoded_buf_size    Size of encoded_buf in bytes
 * \param[out]  encoded_buf_len     Encoded and signed payload len in bytes
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_si_tflm_hello(psa_key_id_t *key_id,
			       const float *input,
			       size_t input_length,
			       uint8_t *encoded_buf,
			       size_t encoded_buf_size,
			       size_t *encoded_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* __TFM_PARTITION_TFLM_H__ */
