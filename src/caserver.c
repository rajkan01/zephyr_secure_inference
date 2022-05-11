/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <net/http_client.h>
#include <nanocbor/nanocbor.h>

#include "test_certs.h"
#include <util_sformat.h>

#include <provision.h>

#include <logging/log.h>
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#define HTTPS_PORT 1443
#define HTTPS_PORT_TEXT "1443"
#define HOST CONFIG_BOOTSTRAP_SERVER_HOST

/* These tags need to be globally allocated across the app. */
#define APP_CA_CERT_TAG 5
#define APP_SERVER_CRT_TAG 6
#define APP_SERVER_KEY_TAG 7

static sec_tag_t m_sec_tags[] = {
	APP_CA_CERT_TAG,
	APP_SERVER_CRT_TAG,
	APP_SERVER_KEY_TAG,
};

/* DNS lookup data. */
static struct zsock_addrinfo hints;
static struct zsock_addrinfo *haddr;

static const char *cbor_header[] = {
	"Content-Type: application/cbor\r\n",
	0,
};

#define RECV_BUF_LEN 1025

static uint8_t recv_buf[RECV_BUF_LEN];

#ifdef DEBUG_WALK_CBOR
/* Walk a CBOR structure, at least with certain fields.  This can help
 * us understand how to use the nanocbor API.
 */
static int walk_cbor(struct nanocbor_value *item)
{
	int kind;
	int res;
	struct nanocbor_value map;
	uint32_t ukey;
	const uint8_t *buf;
	size_t buf_len;

	while (!nanocbor_at_end(item)) {
		kind = nanocbor_get_type(item);
		switch (kind) {
		case NANOCBOR_TYPE_UINT:
			res = nanocbor_get_uint32(item, &ukey);
			if (res < 0)
				return res;
			LOG_INF("uint: %d", ukey);
			break;
		case NANOCBOR_TYPE_BSTR:
			res = nanocbor_get_bstr(item, &buf, &buf_len);
			if (res < 0)
				return res;
			LOG_INF("bstr: %d bytes", buf_len);
			break;
		case NANOCBOR_TYPE_TSTR:
			res = nanocbor_get_tstr(item, &buf, &buf_len);
			if (res < 0)
				return res;
			LOG_INF("tstr: %d bytes", buf_len);
			break;
		case NANOCBOR_TYPE_MAP:
			res = nanocbor_enter_map(item, &map);
			if (res < 0)
				return res;
			LOG_INF("map: %d entries", map.remaining);
			res = walk_cbor(&map);
			if (res < 0)
				return res;
			nanocbor_leave_container(item, &map);
			break;
		default:
			LOG_ERR("Unhandled cbor: %d", kind);
			return -EIO;
		}
	}

	return 0;
}
#endif /* DEBUG_WALK_CBOR */

static int decode_ca_response(struct provision_data *prov, const uint8_t *buf, size_t len)
{
	struct nanocbor_value decode;
	struct nanocbor_value map;
	int res;
	uint32_t value;
	uint32_t port;

#ifdef DEBUG_WALK_CBOR
	nanocbor_decoder_init(&decode, buf, len);
	walk_cbor(&decode);
#endif

	nanocbor_decoder_init(&decode, buf, len);

	res = nanocbor_enter_map(&decode, &map);
	if (res < 0) {
		return res;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	/* This first key must be 1 for status. */
	if (value != 1) {
		return -EINVAL;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	/* The second key must be 2 for the certificate. */
	if (value != 2) {
		return -EINVAL;
	}

	res = nanocbor_get_bstr(&map, &prov->cert_der, &prov->cert_der_len);
	if (res < 0) {
		return res;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	/* The third key myst be 3, for the hubname. */
	if (value != 3) {
		return -EINVAL;
	}

	res = nanocbor_get_tstr(&map, (const uint8_t **)&prov->hubname, &prov->hubname_len);
	if (res < 0) {
		return res;
	}

	res = nanocbor_get_uint32(&map, &value);
	if (res < 0) {
		return res;
	}

	/* The last key must be 4, for the port. */
	if (value != 4) {
		return -EINVAL;
	}

	res = nanocbor_get_uint32(&map, &port);
	if (res < 0) {
		return res;
	}
	prov->hubport = port;

	nanocbor_leave_container(&decode, &map);
	return res;
}

static void caresponse_cb(struct http_response *rsp, enum http_final_call final_data,
			  void *user_data)
{
	struct provision_data prov;
	int res;

	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data %zd bytes", rsp->data_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("All data received %zd bytes", rsp->data_len);
	}

	LOG_INF("Response to req");
	LOG_INF("Status %s", rsp->http_status);

	res = decode_ca_response(&prov, rsp->body_frag_start, rsp->content_length);
	LOG_INF("Result: %d", res);
	LOG_INF("cert: %d bytes", prov.cert_der_len);

	if (res >= 0) {
		/* Provided the provisioning worked, store the information in persistent storage. */
		res = provision_store(&prov);
	}

	/* TODO: How should we handle errors here.  Presumably, we won't store
	 * the provision data, and may retry later. */

	struct sf_hex_tbl_fmt fmt = {
		.ascii = 1,
		.addr_label = 1,
		.addr = 0,
	};
	sf_hex_tabulate_16(&fmt, prov.cert_der, prov.cert_der_len);
}

static int get_caserver_addrinfo(void)
{
	int retries = 3;
	int rc = -EINVAL;

	while (retries--) {
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;

		rc = zsock_getaddrinfo(HOST, HTTPS_PORT_TEXT, &hints, &haddr);
		if (rc == 0) {
			LOG_INF("Got DNS for linaroca");
			return 0;
		}
	}

	return rc;
}

/* Query the CA server, sending it the following request as posted
 * data.
 */
int caserver_cr(unsigned char *payload, size_t payload_len)
{
	int rc;
	rc = get_caserver_addrinfo();
	if (rc < 0) {
		return rc;
	}

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		return sock;
	}

	/* Add credentials. */
	rc = setsockopt(sock, SOL_TLS, TLS_HOSTNAME, HOST, sizeof(HOST));
	if (rc < 0) {
		LOG_ERR("Failed to set %s TLS_HOSTNAME option (%d)",
			"IPv4", -errno);
		return rc;
	}

	rc = tls_credential_add(APP_CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, caroot_crt,
				caroot_crt_len);
	if (rc < 0) {
		LOG_ERR("Failed to register public certificate: %d", rc);
		return rc;
	}

	rc = tls_credential_add(APP_SERVER_CRT_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE,
				bootstrap_crt, bootstrap_crt_len);
	if (rc < 0) {
		LOG_ERR("Failed to register bootstrap certificate: %d", rc);
		return rc;
	}

	rc = tls_credential_add(APP_SERVER_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY, bootstrap_key,
				bootstrap_key_len);
	if (rc < 0) {
		LOG_ERR("Failed to register bootstrap certificate key: %d", rc);
		return rc;
	}

	// TODO: How do we get these symbols without bringing in all
	// of the MbedTLS headers?
	int peer_verify = 2;
	rc = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
	if (rc < 0) {
		LOG_ERR("Failed to set peer verify");
		return rc;
	}

	rc = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, m_sec_tags, 3 * sizeof(sec_tag_t));
	if (rc < 0) {
		LOG_ERR("Failed to set tls configuration");
		return rc;
	}

	struct sockaddr_in daddr;

	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(HTTPS_PORT);

	net_ipaddr_copy(&daddr.sin_addr, &net_sin(haddr->ai_addr)->sin_addr);

	/* Attempt to connect */
	rc = connect(sock, (struct sockaddr *)&daddr, sizeof(daddr));
	if (rc < 0) {
		LOG_ERR("Failed to connect to caserver: %d", -errno);
		return rc;
	}

	struct http_request req;
	memset(&req, 0, sizeof(req));

	req.method = HTTP_POST;
	req.url = "/api/v1/cr";
	req.host = HOST;
	req.protocol = "HTTP/1.1";
	req.response = caresponse_cb;
	req.payload = payload;
	req.payload_len = payload_len;
	req.recv_buf = recv_buf;
	req.recv_buf_len = sizeof(recv_buf);
	req.header_fields = cbor_header;

	rc = http_client_req(sock, &req, 5 * MSEC_PER_SEC, "CSR Request");
	LOG_INF("Request result: %d", rc);

	return rc < 0 ? rc : 0;
}
