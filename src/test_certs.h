/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TEST_CERTS_H__
#define __TEST_CERTS_H__

static const unsigned char ca_certificate[] = {
#include "digicert.cer"
};

/* The device certificate should be ASCII in PEM format.  It should
 * start with "-----BEGIN CERTIFICATE-----\r\n", and can easily be
 * made by surrounding each line with quotes, and adding "\r\n" to the
 * end.
 */
static char device_crt[] =
#include "device_crt.txt"
;

/* The device private key should be the output of the binary
 * DER-format key file in hex.  This can be generated, for example,
 * with `xxd -i`.
 */
static unsigned char device_key[] = {
#include "device_key.txt"
};

#endif /* not __TEST_CERTS_H__ */
