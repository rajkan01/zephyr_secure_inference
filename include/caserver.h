/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CASERVER_H__
#define __CASERVER_H__

/**
 * @brief The context for caserver REST requests.
 */
struct caserver {
	int sock;
};

/**
 * @brief Open a connection to the CA server.
 *
 * @return 0 for success, or a negative errno
 */
int caserver_open(struct caserver *ctx);

/**
 * @brief Close a CA server connection.
 *
 * @return 0 for success, or a negative errno
 */
int caserver_close(struct caserver *ctx);

/* Legacy request.  Request comes from outside. */
int caserver_cr(struct caserver *ctx, unsigned char *req, size_t req_len);

/**
 * @brief The context needed for the CSR request.
 *
 * All fields are private.  The struct is exposed because the caller
 * is responsible for the allocation of this data.
 */
struct csr_req {
	uint8_t uuid[37];
	uint8_t cbor[1024];
	size_t cbor_len;
};

/**
 * @brief Perform a CSR request for the given key
 *
 * @return 0 for success, or a negative errno
 */
int caserver_csr(struct caserver *ctx, struct csr_req *req, uint8_t key_idx);

#endif /* not __CASERVER_H__ */
