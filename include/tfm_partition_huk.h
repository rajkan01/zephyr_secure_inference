/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __TFM_PARTITION_HUK_H__
#define __TFM_PARTITION_HUK_H__

#include "tfm_api.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get the public key from HUK export public key service
 *
 * \param[in] key_id                   EC key id for persistent key
 * \param[in] ec_pk_data       Buffer to which exported public key
 *                                     is written into
 * \param[in] ec_pk_data_size  Size of ec_pk_data in bytes
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t psa_huk_get_pubkey(psa_key_id_t *key_id,
				uint8_t *ec_pk_data,
				size_t ec_pk_data_size);

/**
 * \brief Get the UUID from HUK generate UUID service
 *
 * \param[out] uuid          Buffer to write UUID
 * \param[in] uuid_size      Size of UUID buffer
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t psa_huk_get_uuid(void *uuid,
			      size_t uuid_size);

#ifdef __cplusplus
}
#endif

#endif /* __TFM_PARTITION_HUK_H__ */
