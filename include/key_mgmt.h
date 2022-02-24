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
