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
 * @brief Initialise the supplied key context, populating it via calls to
 *        the HUK key derivation partition on the secure side.
 * @brief Takes the supplied reference to a km_key_context_t array, and
 *        populates it with details for the Device Client TLS, COSE sign, and
 *        COSE encrypt keys. This operation will associate a PSA key ID
 *        with each of the three keys types, allowing access to the public key.
 *        This must be called once before the key context can be used.
 *
 * @param ctx      Pointer to the key context
 * @param key_id   Key id.
 * @param label    Unique string to represent the key context.
 */
void km_context_init(km_key_context_t *ctx,
		     km_key_type_t key_id,
		     const unsigned char *label);

#endif /* KEY_MGMT_H */
