/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr.h>
#include <data/json.h>

#include "util_app_log.h"
#include "x509_csr_gen.h"
#include "util_sformat.h"

/*
 * Declare a reference to the application logging interface.
 */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/* Formatting details for displaying hex dumps. */
struct sf_hex_tbl_fmt crp_fmt = {
	.ascii = true,
	.addr_label = true,
	.addr = 0
};

struct csr_json_struct {
	const char *CSR;
};

static const struct json_obj_descr csr_json_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct csr_json_struct, CSR, JSON_TOK_STRING)
};

#if HASH_CALC_USE_MBEDTLS
int x509_csr_hash_calc(const uint8_t *buf,
		       const size_t buf_len,
		       uint8_t *hash)
{
	mbedtls_md_context_t md_ctx;

	mbedtls_md_setup(&md_ctx,
			 mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			 0);
	mbedtls_md_starts(&md_ctx);
	mbedtls_md_update(&md_ctx, buf, buf_len);

	if (mbedtls_md_finish(&md_ctx, hash)) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}
	printf("x509_csr_hash_calc\n");
	for (int i = 0; i < 64; i++) {
		printf("0x%x, ", hash[i]);
	}
	printf("\n");
	return 0;
}
#endif

int x509_csr_write_pubkey(unsigned char **p, unsigned char *start,
			  const km_key_idx_t key_idx)
{
	km_key_context_t *ctx = km_context_get();
	size_t buffer_size = (size_t)(*p - start);

	if (p == NULL || *p == NULL || start == NULL) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (*p < start || buffer_size < KM_PUBLIC_KEY_SIZE) {
		return(MBEDTLS_ERR_PK_BAD_INPUT_DATA);
	}

	if (km_get_pubkey(start, KM_PUBLIC_KEY_SIZE,
			  ctx[key_idx]) != 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	} else {
		*p -= KM_PUBLIC_KEY_SIZE;
		memmove(*p, start, KM_PUBLIC_KEY_SIZE);
	}

	return((int) KM_PUBLIC_KEY_SIZE);
}

int x509_csr_write_pubkey_der(const km_key_idx_t key_idx,
			      unsigned char *buf,
			      size_t size)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned char *c;
	size_t len = 0, par_len = 0,
	       oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1);
	mbedtls_pk_type_t pk_type = MBEDTLS_PK_ECKEY;
	const char *oid = MBEDTLS_OID_EC_GRP_SECP256R1;

	if (buf == NULL) {
		return(MBEDTLS_ERR_PK_BAD_INPUT_DATA);
	}

	if (size == 0) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	c = buf + size;

	MBEDTLS_ASN1_CHK_ADD(len, x509_csr_write_pubkey(&c, buf, key_idx));

	if (c - buf < 1) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	/*
	 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 *       algorithm            AlgorithmIdentifier,
	 *       subjectPublicKey     BIT STRING }
	 */
	*--c = 0;
	len += 1;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_BIT_STRING));

	/* Write EC algorithm parameters; that's akin
	 * to pk_write_ec_param() above. */
	MBEDTLS_ASN1_CHK_ADD(par_len,
			     mbedtls_asn1_write_oid(&c,
						    buf,
						    oid,
						    oid_len));


	if ((ret = mbedtls_oid_get_oid_by_pk_alg(pk_type,
						 &oid,
						 &oid_len)) != 0) {
		return(ret);
	}

	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_algorithm_identifier(&c,
								     buf,
								     oid,
								     oid_len,
								     par_len));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(&c,
						    buf,
						    MBEDTLS_ASN1_CONSTRUCTED |
						    MBEDTLS_ASN1_SEQUENCE));

	return((int) len);
}

static int x509_csr_write_mpibuf(unsigned char **p, unsigned char *start,
				 size_t n_len)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t len = 0;

	if ((size_t)(*p - start) < n_len) {
		return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
	}

	len = n_len;
	*p -= len;
	memmove(*p, start, len);

	/* ASN.1 DER encoding requires minimal length, so skip leading 0s.
	 * Neither r nor s should be 0, but as a failsafe measure, still detect
	 * that rather than overflowing the buffer. */
	while (len > 0 && **p == 0x00) {
		++(*p);
		--len;
	}

	/* this is only reached if the signature was invalid */
	if (len == 0) {
		return(MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
	}

	/* if the msb is 1, ASN.1 requires that we prepend a 0.
	 * Neither r nor s can be 0, so we can assume len > 0 at all times. */
	if (**p & 0x80) {
		if (*p - start < 1) {
			return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
		}

		*--(*p) = 0x00;
		len += 1;
	}

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(p,
						    start,
						    MBEDTLS_ASN1_INTEGER));

	return((int) len);
}

static int x509_csr_write_sign(km_key_idx_t key_idx,
			       uint8_t *csr_data,
			       size_t csr_data_size,
			       uint8_t *sig,
			       size_t sig_size,
			       size_t *sig_len)
{
	unsigned char *p = sig + sig_size;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	size_t len = 0;
	km_key_context_t *ctx = km_context_get();
	psa_status_t status;

	/* Send the CSR payload to HUK hash sign tfm service which calculate hash
	 * and sign, return filled sig buffer with hash signature
	 */
	status =  psa_huk_hash_sign(&ctx[key_idx].key_id,
				    csr_data,
				    csr_data_size,
				    sig,
				    sig_size,
				    sig_len);
	if (status != PSA_SUCCESS) {
		return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
	}

	const size_t rs_len = *sig_len / 2;
	/* transcode sign to ASN.1 sequence */
	MBEDTLS_ASN1_CHK_ADD(len, x509_csr_write_mpibuf(&p, sig + rs_len, rs_len));
	MBEDTLS_ASN1_CHK_ADD(len, x509_csr_write_mpibuf(&p, sig, rs_len));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, sig, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(&p,
						    sig,
						    MBEDTLS_ASN1_CONSTRUCTED |
						    MBEDTLS_ASN1_SEQUENCE));

	memmove(sig, p, len);
	*sig_len = len;
	return 0;

}

static int x509_csr_gen_der(mbedtls_x509write_csr *ctx,
			    unsigned char *buf,
			    size_t size,
			    const km_key_idx_t key_idx)
{
	unsigned char *sig;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	const char *sig_oid;
	size_t sig_oid_len = 0;
	unsigned char *c, *c2;
	size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECDSA;
	size_t sig_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;

	if ((sig = mbedtls_calloc(1, MBEDTLS_PK_SIGNATURE_MAX_SIZE)) == NULL) {
		return(MBEDTLS_ERR_X509_ALLOC_FAILED);
	}
	/* Write the CSR backwards starting from the end of buf */
	c = buf + size;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c, buf,
				     MBEDTLS_ASN1_CONSTRUCTED |
				     MBEDTLS_ASN1_CONTEXT_SPECIFIC));

	MBEDTLS_ASN1_CHK_ADD(pub_len,
			     x509_csr_write_pubkey_der(key_idx,
						       buf,
						       c - buf));
	c -= pub_len;
	len += pub_len;

	/*
	 *  Subject  ::=  Name
	 */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c,
							   buf,
							   ctx->MBEDTLS_PRIVATE(subject)));

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c, buf,
				     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/*
	 * Sign the written CSR data into the sig buffer
	 * Note: hash errors can happen only after an internal error
	 */
	ret = x509_csr_write_sign(key_idx,
				  (uint8_t *)c,
				  len,
				  (uint8_t *)sig,
				  sig_size,
				  &sig_len);


	if (ret != 0) {
		return(ret);
	}

	if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg,
						  ctx->MBEDTLS_PRIVATE(md_alg),
						  &sig_oid,
						  &sig_oid_len)) != 0) {
		return(ret);
	}

	/*
	 * Move the written CSR data to the start of buf to create space for
	 * writing the signature into buf.
	 */
	memmove(buf, c, len);

	/*
	 * Write sig and its OID into buf backwards from the end of buf.
	 * Note: mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
	 * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
	 */
	c2 = buf + size;
	MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len,
			     mbedtls_x509_write_sig(&c2,
						    buf + len,
						    sig_oid,
						    sig_oid_len,
						    sig,
						    sig_len));

	/*
	 * Compact the space between the CSR data and signature by moving the
	 * CSR data to the start of the signature.
	 */
	c2 -= len;
	memmove(c2, buf, len);

	/* ASN encode the total size and tag the CSR data with it. */
	len += sig_and_oid_len;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c2, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len,
			     mbedtls_asn1_write_tag(
				     &c2,
				     buf,
				     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/* Zero the unused bytes at the start of buf */
	memset(buf, 0, c2 - buf);

	mbedtls_free(sig);

	return((int) len);
}

#if defined(MBEDTLS_PEM_WRITE_C)
int x509_csr_pem(mbedtls_x509write_csr *ctx,
		 unsigned char *buf,
		 size_t size,
		 const km_key_idx_t key_idx)
{
	int ret = 0;
	size_t olen = 0;

	/* Generate CSR in DER format */
	if ((ret = x509_csr_gen_der(ctx,
				    buf,
				    size,
				    key_idx)) < 0) {
		return(ret);
	}
	/* Convert CSR from DER to PEM format using MbedTLS */
	if ((ret = mbedtls_pem_write_buffer(X509_CSR_PEM_BEGIN,
					    X509_CSR_PEM_END,
					    buf + size - ret,
					    ret,
					    buf,
					    size,
					    &olen)) != 0) {
		return(ret);
	}

	return(ret);
}

/**
 * @brief Generates device certificate signing request (CSR) using Mbed TLS
 * X.509 and HUK CSR ROT service.
 */
psa_status_t x509_csr_generate(const km_key_idx_t key_idx,
			       unsigned char *csr,
			       size_t csr_len,
			       unsigned char *uuid,
			       size_t uuid_size)
{
	psa_status_t status;
	km_key_context_t *ctx = km_context_get();
	mbedtls_x509write_csr req;

	/* length of CSR subject name is calculated as
	 * strlen(O=Linaro,CN=) + UUID length + OU lenth + null character
	 */
	char csr_subject_name[80] = { 0 };

	printf("\nGenerating X.509 CSR for '%s' key:\n", ctx[key_idx].label);

	/* CSR subject name: O=Linaro,CN= <UUID>,OU=<Key label> */
	sprintf(csr_subject_name, "%s%s%s%s%s", X509_CSR_SUB_ORG,
		",CN=", uuid, ",OU=", ctx[key_idx].label);

	printf("Subject: %s\n", csr_subject_name);

	/* Initialize Mbed TLS structures. */
	mbedtls_x509write_csr_init(&req);
	memset(csr, 0, csr_len);

	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

	/* Adding subject name to CSR */
	status = mbedtls_x509write_csr_set_subject_name(&req, csr_subject_name);
	if (status != 0) {
		LOG_ERR("Setting a CSR subject name failed with error %d", status);
		goto err;
	}

	/* Create device Certificate Signing Request */
	status = x509_csr_pem(&req,
			      csr,
			      csr_len,
			      key_idx);
	if (status < 0) {
		LOG_ERR("CSR PEM format generation failed with error -0x%04x",
			(unsigned int) -status);
		goto err;
	}

	al_dump_log();

err:
	al_dump_log();
	mbedtls_x509write_csr_free(&req);
	return status;
}

psa_status_t x509_csr_json_encode(unsigned char *csr,
				  unsigned char *csr_json_buff,
				  size_t csr_json_buff_len)
{
	psa_status_t status = PSA_SUCCESS;


	struct csr_json_struct csr_json = {
		.CSR = csr
	};

	/*
	 * Encoding CSR as JSON
	 */
	status = json_obj_encode_buf(csr_json_descr,
				     ARRAY_SIZE(csr_json_descr),
				     &csr_json,
				     csr_json_buff,
				     csr_json_buff_len);
	if (status != 0) {
		LOG_ERR("CSR encoding to JSON format failed with error 0x%04x",
			status);
	}
	return status;
}

#endif  /* MBEDTLS_PEM_WRITE_C */
