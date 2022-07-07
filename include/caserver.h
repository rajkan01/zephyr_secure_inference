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

#endif /* not __CASERVER_H__ */
