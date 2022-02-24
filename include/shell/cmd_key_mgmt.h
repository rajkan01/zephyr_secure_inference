/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/error.h"
#include "keys/key_mgmt.h"

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT
/**
 * @brief Get the uuid
 *
 * @param uuid       Pointer to the buffer to store the uuid.
 * @param uuid_size  Size of uuid buffer.
 *
 * @return psa_status_t
 */
psa_status_t psa_get_uuid(unsigned char *uuid, size_t uuid_size);

/**
 * @brief Get the public key
 *
 * @param public_key      Pointer to the buffer to store the public key.
 * @param public_key_len  Public key length.
 * @param ctx             Key context
 *
 * @return psa_status_t
 */
psa_status_t psa_get_pubkey(uint8_t *public_key,
			    size_t public_key_len,
			    km_key_context_t ctx);
#endif
