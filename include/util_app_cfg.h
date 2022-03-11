/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include "psa/error.h"
#include "key_mgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The struct used to persist config data to secure storage.
 *
 * The first 6 bytes of this struct should remain consistent in any future
 * firmware updates, since they can be used to identify to layout of the rest
 * of the struct in cases where config data version management becomes
 * a necessity.
 */
struct cfg_data {
	/**
	 * @brief Magic number for config data payloads (0x55CFDA7A).
	 */
	uint32_t magic;

	/**
	 * @brief The version number for the stored config record.
	 *
	 * This number should be incremented any time the config_data struct
	 * definition changes to allow version management of config data at
	 * the application level.
	 */
	uint16_t version;

	/**
	 * @brief Device TLS certificate (KEY_ID_CLIENT_TLS).
	 */
	km_x509_cert_t cert_device_tls;

	/**
	 * @brief COSE signing certificate (KEY_ID_C_SIGN).
	 */
	km_x509_cert_t cert_device_cose_sign;

	/**
	 * @brief COSE client encryption certificate (KEY_ID_C_ENCRYPT).
	 */
	km_x509_cert_t cert_device_cose_encrypt;

	/**
	 * @brief Signing certificate for the device provisioning CA.
	 *
	 * The certificate provided by the CA to verify signatures on CA-issued
	 * certificates.
	 */
	km_x509_cert_t cert_ca_sign;

	/**
	 * @brief TLS certificate for the device provisioning CA.
	 *
	 * The certificate used to securely connect to the REST API (etc.) on
	 * the CA to register a new device.
	 */
	km_x509_cert_t cert_ca_tls;

	/**
	 * @brief TLS certificate for the MQTT broker.
	 *
	 * The certificate used to securely connect to the MQTT broker. This is
	 * usually the CA that generated the MQTT broker's server certificate
	 * (digicert for Azure IoT Hub, etc.).
	 */
	km_x509_cert_t cert_mqtt_tls;
};

/**
 * @brief Creates a new config record in secure storage.
 *
 * @return #PSA_SUCCESS on success, otherwise a appropriate psa_status_t code.
 */
psa_status_t cfg_create_data(void);

/**
 * @brief Attempts to load the config record from secure storage. If the
 *        record is not found in secure storage, a new record will be created
 *        using default config settings.
 *
 * @param p_cfg_data Pointer to the cfg_data struct where the config data
 *        should be assigned once loaded.
 *
 * @return #PSA_SUCCESS on success, otherwise a appropriate psa_status_t code.
 */
psa_status_t cfg_load_data(struct cfg_data *p_cfg_data);

#ifdef __cplusplus
}
#endif
