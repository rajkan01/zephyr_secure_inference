/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef KEY_MGMT_H
#define KEY_MGMT_H

#include "psa/crypto_types.h"

/** EC public keys are 65 bytes. */
#define KM_PUBLIC_KEY_SIZE (65)

/** Define the index for the key in the key context array. */
typedef enum {
	KEY_CLIENT_TLS = 0,             /**< TLS client key ID */
	KEY_C_SIGN,                     /**< COSE SIGN key ID */
	KEY_C_ENCRYPT,                  /**< COSE ENCRYPT key ID */
	KEY_COUNT,                      /**< Number of keys present */
} km_key_idx_t;

/** Inidicates key provisioning status. */
typedef enum {
	X_509_CERT_GEN = 0,     /**< X.509 certificate generated */
	KEY_GEN,                /**< Key generated */
	NONE,
} km_key_sts_t;

/** ID in the HUK key derivation service for the specified key. */
typedef enum {
	KEY_ID_CLIENT_TLS       = 0x5001,       /**< Client TLS key ID */
	KEY_ID_C_SIGN           = 0x5002,       /**< COSE SIGN key ID */
	KEY_ID_C_ENCRYPT        = 0x5003,       /**< COSE ENCRYPT key ID */
} km_key_type_t;

typedef struct {
	psa_key_id_t key_id;
	char label[32];
	km_key_sts_t status;
} km_key_context_t;

/**
 * @brief Get the HUK-derived UUID from the secure partition.
 *
 * @param uuid       Pointer to the buffer to store the UUID.
 * @param uuid_size  Size of UUID buffer.
 *
 * @return psa_status_t
 */
psa_status_t km_get_uuid(unsigned char *uuid, size_t uuid_size);

/**
 * @brief Get the public key from the HUK-derived key on the secure partition.
 *
 * @param public_key      Pointer to the buffer to store the public key.
 * @param public_key_len  Public key buffer length.
 * @param ctx             Key context
 *
 * @return psa_status_t
 */
psa_status_t km_get_pubkey(uint8_t *public_key,
			   size_t public_key_len,
			   km_key_context_t ctx);

/**
 * @brief Gets a reference to the km_key_context_t array in memory. The data this
 *        pointer references is NULL-initialised by default, and needs to be
 *        initialised before it can be used.
 *
 * @return Returns a pointer to the key context array
 */
km_key_context_t *km_context_get();

/**
 * @brief Initialise the key context with the EC keys derived from the HUK at
 *        secure boot. This provides us with the key handles required to
 *        request the public key, or to request operations based on these
 *        keys.
 */
void km_keys_init(void);

#endif /* KEY_MGMT_H */
