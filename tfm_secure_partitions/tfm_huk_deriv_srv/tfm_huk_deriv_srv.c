/*
 * Copyright (c) 2021-2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "tfm_secure_api.h"
#include "tfm_api.h"

#include "cbor_cose_api.h"
#include "tfm_sp_log.h"
#include "tfm_crypto_defs.h"
#include "psa/crypto.h"
#include "psa/service.h"
#include "psa_manifest/tfm_huk_deriv_srv.h"
#include "tfm_huk_deriv_srv_api.h"

#define KEY_LEN_BYTES 16
/* This macro appends an optional HUK_DERIV_LABEL_EXTRA string to the
 * label used for key derivation, enabling key diversity during testing
 * on emulated platforms with a fixed HUK value.
 * It can be set at compile time via '-DHUK_DERIV_LABEL_EXTRA=value'.
 */
#define LABEL_CONCAT(A) #A HUK_DERIV_LABEL_EXTRA
#define LABEL_HI    LABEL_CONCAT(_EC_PRIV_KEY_HI)
#define LABEL_LO    LABEL_CONCAT(_EC_PRIV_KEY_LO)
#define LABEL_UUID  LABEL_CONCAT(UUID)

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

#define UUID_STR_LEN ((KEY_LEN_BYTES * 2) + 4 + 1)
#define UUID_7TH_BYTE_MASK  0x0f        /* 0b0000_1111*/
#define UUID_7TH_BYTE_SET   0x40        /* 0b0100_0000 */
#define UUID_9TH_BYTE_MASK  0x3f        /* 0b0011_1111*/
#define UUID_9TH_BYTE_SET   0x80        /* 0b1000_0000*/
#define TFM_HUK_ASN1_CONSTRUCTED      0x20
#define TFM_HUK_ASN1_SEQUENCE         0x10
#define TFM_HUK_ASN1_DATA_LENGTH_0_255 1

/* To verify CSR ASN.1 tag and length of the payload */
static psa_status_t tfm_huk_csr_verify(unsigned char *csr_data,
				       size_t csr_len, int tag)
{
	unsigned char *csr_start = csr_data,
		      *csr_end = (csr_data + csr_len);
	size_t len;

	if ((csr_end - csr_start) < 1) {
		return(PSA_ERROR_INSUFFICIENT_DATA);
	}

	if (*csr_start != tag) {
		return(PSA_ERROR_INVALID_ARGUMENT);
	}

	csr_start++;

	/* Check CSR data payload length between 0 to 255 */
	if ((*csr_start & 0x7F) == TFM_HUK_ASN1_DATA_LENGTH_0_255) {
		len = csr_start[1];
		csr_start += 2;
	} else {
		return(PSA_ERROR_NOT_SUPPORTED);
	}

	if (len != ((size_t)(csr_end - csr_start))) {
		return(PSA_ERROR_SERVICE_FAILURE);
	}
	return PSA_SUCCESS;
}

static psa_status_t tfm_encode_random_bytes_to_uuid(uint8_t *random_bytes,
						    size_t random_bytes_len,
						    uint8_t *uuid_buf,
						    size_t uuid_buf_len)
{
	int j = 0;
	int hyphen_index = 8;

	if (random_bytes_len != KEY_LEN_BYTES) {
		return PSA_ERROR_INSUFFICIENT_DATA;
	}

	if (uuid_buf_len != UUID_STR_LEN) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	for (int i = 0; i < random_bytes_len; i++) {
		if (i == 6) {
			random_bytes[i] =
				(random_bytes[i] & UUID_7TH_BYTE_MASK) |
				UUID_7TH_BYTE_SET;
		}
		if (i == 8) {
			random_bytes[i] =
				(random_bytes[i] & UUID_9TH_BYTE_MASK) |
				UUID_9TH_BYTE_SET;
		}

		uuid_buf[j++] = hex_digits[random_bytes[i] >> 4];
		uuid_buf[j++] = hex_digits[random_bytes[i] & 0x0f];

		if (j == hyphen_index) {
			uuid_buf[j++] = '-';
			if (hyphen_index == 23) {
				hyphen_index = 0;
			} else {
				hyphen_index += 5;
			}
		}
	}
	uuid_buf[j] = '\0';
}

static psa_status_t tfm_huk_deriv_unique_key(uint8_t *key_data,
					     size_t key_data_size,
					     size_t *key_data_len,
					     uint8_t *label,
					     size_t label_size)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_id_t derived_key_id;

	if (key_data_size < KEY_LEN_BYTES) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	if (label == NULL || label_size == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Currently, MbedTLS does not support key derivation for Elliptic curves.
	 * There is a PR https://github.com/ARMmbed/mbedtls/pull/5139 in progress
	 * though. Once this PR is merged, TF-M updates MbedTLS and finally, once
	 * Zephyr updates to latest TF-M, then we can use derive key/s for Elliptic
	 * curve instead of using symmetric keys as starting point for Elliptic
	 * curve key derivation.
	 */

	/* Set the key attributes for the key */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);

	/* Set the algorithm, key type and the number of bits of the key. This is
	 * mandatory for key derivation. Setting these attributes will ensure that
	 * derived key is in accordance with the standard, if any.
	 */
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(KEY_LEN_BYTES));

	/* Set up a key derivation operation with HUK derivation as the alg */
	status = psa_key_derivation_setup(&op, TFM_CRYPTO_ALG_HUK_DERIVATION);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Supply the UUID label as an input to the key derivation */
	status = psa_key_derivation_input_bytes(&op,
						PSA_KEY_DERIVATION_INPUT_LABEL,
						label,
						label_size);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Create the storage key from the key derivation operation */
	status = psa_key_derivation_output_key(&attributes, &op, &derived_key_id);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	status =  psa_export_key(derived_key_id, key_data, key_data_size, key_data_len);

	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Free resources associated with the key derivation operation */
	status = psa_key_derivation_abort(&op);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_destroy_key(derived_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INFFMT("[HUK deriv unique key] psa_destroy_key returned: %d \n", status);
		return status;
	}

	return PSA_SUCCESS;

err_release_op:
	(void)psa_key_derivation_abort(&op);

	return status;
}

static psa_status_t tfm_huk_deriv_ec_key(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	uint8_t ec_priv_key_data[KEY_LEN_BYTES * 2] = { 0 };
	size_t ec_priv_key_data_len = 0;
	psa_key_usage_t key_usage_flag;

	// Check size of invec parameters
	if (msg->in_size[0] == 0 ||
	    msg->in_size[1] != sizeof(psa_key_id_t)) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	uint8_t label_hi[32] = { 0 };
	uint8_t label_lo[32] = { 0 };
	uint8_t rx_label[32] = { 0 };
	psa_key_id_t key_id;

	psa_read(msg->handle, 0, &rx_label, msg->in_size[0]);
	psa_read(msg->handle, 1, &key_id, msg->in_size[1]);
	psa_read(msg->handle, 2, &key_usage_flag, msg->in_size[2]);

	/* Add LABEL_HI to rx_label to create label_hi. */
	sprintf((char *)label_hi, "%s%s", rx_label, LABEL_HI);

	/* Add LABEL_LO to rx_label to create label_lo. */
	sprintf((char *)label_lo, "%s%s", rx_label, LABEL_LO);

	/* For MPS2 AN521 platform, TF-M always returns a 16-byte sample key
	 * as the HUK derived key. But the size of EC private key is 32-bytes.
	 * Therefore, we decided to call HUK based key derivation twice.
	 */
	status = tfm_huk_deriv_unique_key(ec_priv_key_data,
					  KEY_LEN_BYTES,
					  &ec_priv_key_data_len,
					  label_hi,
					  strlen((char *)label_hi));

	if (status != PSA_SUCCESS) {
		return status;
	}

	status = tfm_huk_deriv_unique_key(&ec_priv_key_data[ec_priv_key_data_len],
					  KEY_LEN_BYTES,
					  &ec_priv_key_data_len,
					  label_lo,
					  strlen((char *)label_lo));

	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_type_t key_type =
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
	psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_handle_t tflm_cose_key_handle = 0;
	/* Setup the key's attributes before the creation request. */
	psa_set_key_id(&key_attributes, key_id);
	psa_set_key_usage_flags(&key_attributes, key_usage_flag);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, key_type);

	status = psa_import_key(&key_attributes,
				ec_priv_key_data,
				sizeof(ec_priv_key_data),
				&tflm_cose_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK deriv unique key] psa_import_key returned: %d \n", status);
		return status;
	}
	status = psa_close_key(tflm_cose_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK deriv unique key] psa_close_key returned: %d \n", status);
	}

	return status;
}


static psa_status_t tfm_huk_export_pubkey(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	psa_key_id_t key_id = 0;
	psa_key_handle_t key_handle;
	uint8_t data_out[65] = { 0 };         /* EC public key = 65 bytes. */
	size_t data_len;

	psa_read(msg->handle, 0, &key_id, msg->in_size[0]);
	status = psa_open_key(key_id, &key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK export pubkey service] psa_open_key returned: %d \n", status);
		goto err;
	}

	status = psa_export_public_key(key_handle,
				       data_out,
				       sizeof(data_out),
				       &data_len);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK export pubkey service] psa_export_public_key returned: %d \n", status);
		goto err;
	}

	status = psa_close_key(key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK export pubkey service] psa_close_key returned: %d \n", status);
		goto err;
	}
	psa_write(msg->handle, 0, data_out, data_len);
err:
	return status;
}

static psa_status_t tfm_huk_cose_encode_sign
	(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	huk_enc_format_t enc_format;
	uint8_t inf_val_encoded_buf[msg->out_size[0]];
	size_t inf_val_encoded_buf_len = 0;
	float inf_value = 0;

	psa_read(msg->handle, 1, &enc_format, msg->in_size[1]);
	psa_read(msg->handle, 0, &inf_value, msg->in_size[0]);

	if (enc_format == HUK_ENC_CBOR) {
		status = tfm_cbor_encode(inf_value,
					 inf_val_encoded_buf,
					 msg->out_size[0],
					 &inf_val_encoded_buf_len);
		if (status != PSA_SUCCESS) {
			LOG_ERRFMT(
				"[HUK COSE service] Failed to encode inference value: %d \n",
				status);
			return status;
		}
	} else if (enc_format == HUK_ENC_COSE_SIGN1) {
		status = tfm_cose_encode_sign(HUK_COSE_SIGN,
					      inf_value,
					      inf_val_encoded_buf,
					      msg->out_size[0],
					      &inf_val_encoded_buf_len);
		if (status != PSA_SUCCESS) {
			LOG_ERRFMT(
				"[HUK COSE service] tfm_cose_encode_sign returned: %d \n",
				status);
			return status;
		}

	} else {
		LOG_ERRFMT("[HUK COSE service] Invalid encode format \n");
		return PSA_ERROR_NOT_SUPPORTED;
	}
	psa_write(msg->handle,
		  0,
		  inf_val_encoded_buf,
		  inf_val_encoded_buf_len);
	psa_write(msg->handle,
		  1,
		  &inf_val_encoded_buf_len,
		  sizeof(inf_val_encoded_buf_len));
	return status;
}

/* Calculate the SHA256 hash value of the given CSR payload and sign the hash
 * value using the private key of the given key ID.
 */
static psa_status_t tfm_huk_hash_sign_csr(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	psa_algorithm_t psa_alg_id = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_handle_t key_handle;
	size_t signature_len;
	unsigned char hash[64];
	psa_key_id_t key_id = 0;
	size_t csr_data_size = msg->in_size[1];
	uint8_t csr_data[csr_data_size],
		sig[64];
	psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
	size_t hash_len;
	psa_algorithm_t hash_alg = PSA_ALG_SHA_256;

	psa_read(msg->handle, 0, &key_id, msg->in_size[0]);
	psa_read(msg->handle, 1, csr_data, msg->in_size[1]);

	/* Verify CSR ASN.1 tag and length of the payload in bytes to
	 * avoid fake payload getting signed by this service
	 */
	status = tfm_huk_csr_verify(csr_data,
				    msg->in_size[1],
				    TFM_HUK_ASN1_CONSTRUCTED | TFM_HUK_ASN1_SEQUENCE);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT(
			"[HUK CSR sign service] tfm_huk_csr_verify failed with: %d \n",
			status);
		goto err;
	} else {
		LOG_INFFMT(
			"[HUK CSR sign service] Verified ASN.1 tag and length of the payload\n");
	}

	status = psa_open_key(key_id, &key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT(
			"[HUK CSR sign service] psa_open_key returned: %d \n", status);
		goto err;
	}
	LOG_INFFMT("[HUK CSR sign service] Key id: 0x%x\n\n", key_id);
	if (!PSA_ALG_IS_ECDSA(psa_alg_id)) {
		status = PSA_ERROR_NOT_SUPPORTED;
		goto err;
	}
	/* Calculate the SHA256 hash value of the CSR data using PSA crypto service */
	status = psa_hash_setup(&hash_operation, hash_alg);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	status = psa_hash_update(&hash_operation,
				 csr_data,
				 csr_data_size);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	status = psa_hash_finish(&hash_operation,
				 hash,
				 sizeof(hash),
				 &hash_len);
	if (status != PSA_SUCCESS) {
		goto err;
	}

	/* Sign the hash value using PSA crypto service */
	status = psa_sign_hash(key_handle,
			       psa_alg_id,
			       hash,
			       hash_len,
			       sig,                     /* Sig buf */
			       sizeof(sig),             /* Sig buf size */
			       &signature_len);         /* Sig length */
	if (status != PSA_SUCCESS) {
		goto err;
	}

#if PSA_HUK_HASH_SIGN_VERIFY
	status = psa_verify_hash(key_handle,
				 psa_alg_id,
				 hash,
				 hash_len,
				 sig,                   /* Sig buf */
				 signature_len);        /* Sig length */


	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK CSR sign service] hash sign verification failed: %d \n", status);
		goto err;
	} else {
		LOG_ERRFMT("[HUK CSR sign service] hash sign verification passed: %d \n", status);
	}
	LOG_INFFMT("[HUK CSR sign service] Signed value from S-side\n");
	for (int i = 0; i < signature_len; i++) {
		LOG_INFFMT("0x%x, ", sig[i]);
	}
	LOG_INFFMT("\n");
#endif

	status = psa_close_key(key_handle);
	if (status != PSA_SUCCESS) {
		LOG_ERRFMT("[HUK CSR sign service] psa_close_key returned: %d \n", status);
		goto err;
	}
	psa_write(msg->handle,
		  0,
		  sig,
		  signature_len);
	psa_write(msg->handle,
		  1,
		  &signature_len,
		  sizeof(signature_len));
err:
	return status;
}

/* Generates an UUID based on
 * https://datatracker.ietf.org/doc/html/rfc4122#section-4.4
 */
static psa_status_t tfm_huk_gen_uuid(psa_msg_t *msg)
{
	psa_status_t status = PSA_SUCCESS;
	size_t uuid_length;
	static uint8_t uuid_encoded[37] = { 0 };
	uint8_t uuid[16] = { 0 };
	uint8_t uuid_label[32] = { 0 };
	static uint8_t is_uuid_generated = 0;

	/* Populate uuid_label from label macro. */
	sprintf((char *)uuid_label, "%s", LABEL_UUID);

	if (!is_uuid_generated) {
		status = tfm_huk_deriv_unique_key(uuid,
						  sizeof(uuid),
						  &uuid_length,
						  uuid_label,
						  strlen((char *)uuid_label));

		if (status != PSA_SUCCESS) {
			return status;
		}
		tfm_encode_random_bytes_to_uuid(uuid,
						sizeof(uuid),
						uuid_encoded,
						sizeof(uuid_encoded));
		is_uuid_generated = 1;
		LOG_INFFMT("[UUID service] Generated UUID: %s\n", uuid_encoded);
	}
	psa_write(msg->handle, 0, uuid_encoded, sizeof(uuid_encoded));
	return status;
}

static void tfm_huk_deriv_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

psa_status_t tfm_huk_deriv_req_mgr_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_HUK_DERIV_EC_KEY_SIGNAL) {
			tfm_huk_deriv_signal_handle(
				TFM_HUK_DERIV_EC_KEY_SIGNAL,
				tfm_huk_deriv_ec_key);
		} else if (signals & TFM_HUK_EXPORT_PUBKEY_SIGNAL) {
			tfm_huk_deriv_signal_handle(
				TFM_HUK_EXPORT_PUBKEY_SIGNAL,
				tfm_huk_export_pubkey);
		} else if (signals &
			   TFM_HUK_COSE_CBOR_ENC_SIGN_SIGNAL) {
			tfm_huk_deriv_signal_handle(
				TFM_HUK_COSE_CBOR_ENC_SIGN_SIGNAL,
				tfm_huk_cose_encode_sign);
		} else if (signals & TFM_HUK_GEN_UUID_SIGNAL) {
			tfm_huk_deriv_signal_handle(
				TFM_HUK_GEN_UUID_SIGNAL,
				tfm_huk_gen_uuid);
		} else if (signals & TFM_HUK_HASH_SIGN_SIGNAL) {
			tfm_huk_deriv_signal_handle(
				TFM_HUK_HASH_SIGN_SIGNAL,
				tfm_huk_hash_sign_csr);
		} else {
			psa_panic();
		}
	}

	return PSA_SUCCESS;
}
