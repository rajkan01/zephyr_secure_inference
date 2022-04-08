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
 * @brief Size in bytes of the bootstrap private key.
 */
#define APP_CFG_CA_BOOTSTRAP_KEYSZ (121)

/**
 * @brief The struct used to persist config data to secure storage.
 *
 * The first 8 bytes of this struct should remain consistent in any future
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
	 * @brief 32-bit version number data. The first 16 bits represent the
	 *        version of the struct (@ref ver_major and @ref ver_minor). The
	 *        second 16 bits are a counter indicating how many times the struct
	 *        content has been updated (@ref counter).
	 */
	union {
		struct {
			/**
			 * @brief The major version number of the config record,
			 *        identifying how the rest of this struct should be parsed.
			 *
			 * This number should be incremented any time the cfg_data struct
			 * definition changes in a significant manner to allow version
			 * management of config data at the application level, and handling
			 * of different struct definitions across released firmware images.
			 */
			uint8_t major;

			/**
			 * @brief The minor version number of the config record,
			 *        identifying how the rest of this struct should be parsed.
			 *
			 * This number should be incremented any time the cfg_data struct
			 * definition changes to allow version management of config data at
			 * the application level, and handling of different struct 
			 * definitions across released firmware images.
			 */
			uint8_t minor;

			/**
			 * @brief The revision number for the data stored in the config
			 *        record.
			 *
			 * This number should be incremented any time the value(s) assigned
			 * to the cfg_data struct change.
			 */
			uint16_t counter;
		} version;

		/** 32-bit representation of all version bits. */
		uint32_t version_bits;
	};

	/**
	 * @brief X.509 certificates associated with this device.
	 */
	struct {
		/**
		 * @brief Device TLS certificate (KEY_ID_CLIENT_TLS).
		 * 
		 * This client certificate has been signed by the CA and enables mutual
		 * authentication over TLS to an MQTT broker or custom TLS server. It
		 * is unique to this device, containing the device UUID and a unique
		 * serial number assigned by the CA.
		 */
		km_x509_cert_t client_tls;

		/**
		 * @brief COSE signing certificate (KEY_ID_C_SIGN).
		 * 
		 * Contains the certificate associated with the signing key used by
		 * this device to sign COSE SIGN1 payloads.
		 */
		km_x509_cert_t client_cose_sign1;

		/**
		 * @brief COSE client encryption certificate (KEY_ID_C_ENCRYPT).
		 * 
		 * Contains the certificate associated with the device encryption key
		 * used by this device to encrypt COSE ENCRYPT0 payloads.
		 */
		km_x509_cert_t client_cose_encrypt0;

		/**
		 * @brief Client bootstrap certificate for device auth to the CA when
		 *        registering new certificates.
		 *
		 * This client certificate is required to authenticate devices on the
		 * CA during the bootstrapping process in the factory. This enables
		 * limiting certificate registration to devices containing this
		 * certificate and associated private key. This certificate has been
		 * signed with the CA key.
		 * 
		 * With LinaroCA this will be the contents of 'bootstrap_crt.txt'.
		 */
		km_x509_cert_t ca_bootstrap;

		/**
		 * @brief Signing certificate for the device provisioning CA.
		 *
		 * The certificate provided by the CA to verify signatures on CA-issued
		 * certificates.
		 */
		km_x509_cert_t ca_sign;

		/**
		 * @brief Server TLS certificate for the device provisioning CA,
		 *        required to connect to the REST API over TLS.
		 *
		 * The certificate provided by the CA to verify signatures on CA-issued
		 * certificates.
		 */
		km_x509_cert_t ca_host_tls;

		/**
		 * @brief COSE server encryption certificate.
		 * 
		 * Contains the certificate associated with the server's encryption key
		 * used by this device to encrypt COSE ENCRYPTO0 payloads. Both the
		 * client private key and the recipient server's public key are
		 * required to generate the shared secret used to encrypt COSE
		 * ENCRYPT0 payloads.
		 */
		km_x509_cert_t server_cose_encrypt0;

		/**
		 * @brief TLS certificate for the MQTT broker.
		 *
		 * The certificate used to securely connect to the MQTT broker. This is
		 * usually the CA that generated the MQTT broker's server certificate
		 * (digicert for Azure IoT Hub, etc.).
		 */
		km_x509_cert_t mqtt_tls;
	} certs;

	struct {
		/**
		 * @brief Client bootstrap private key associated with
		 *        @ref cert_ca_bootstrap certificate.
		 * 
		 * With LinaroCA this will be the contents of 'bootstrap_key.txt'.
		 */
		uint8_t ca_bootstrap[APP_CFG_CA_BOOTSTRAP_KEYSZ];
	} keys;
};

/**
 * @brief Display the config data via printk.
 * 
 * @param p_cfg_data Pointer to the cfg_data struct where the config data to
 *        display is stored.
 */
void cfg_print_data(struct cfg_data *p_cfg_data);

/**
 * @brief Creates a new config record in secure storage.
 *
 * @return #PSA_SUCCESS on success, otherwise a appropriate psa_status_t code.
 */
psa_status_t cfg_create_data(void);

/**
 * @brief Updates the stored config record in secure storage.
 * 
 * This will automatically increment the config counter field every time the
 * record is persisted.
 * 
 * @param p_cfg_data Pointer to the cfg_data struct where the config data to
 *        persist is stored.
 * 
 * @return psa_status_t 
 */
psa_status_t cfg_update_data(struct cfg_data *p_cfg_data);

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
