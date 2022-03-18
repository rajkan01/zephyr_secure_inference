/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TEST_CERTS_H__
#define __TEST_CERTS_H__

#include <sys/types.h>

/* The root of trust for the MQTT server. */
extern const unsigned char *ca_certificate;
extern const size_t ca_certificate_len;

/* The device certificate should be ASCII in PEM format.  It should
 * start with "-----BEGIN CERTIFICATE-----\r\n", and can easily be
 * made by surrounding each line with quotes, and adding "\r\n" to the
 * end.
 */
extern const char *device_crt;
extern const size_t device_crt_len;

/* The device private key should be the output of the binary
 * DER-format key file in hex.  This can be generated, for example,
 * with `xxd -i`.
 */
extern const unsigned char *device_key;
extern const size_t device_key_len;

/* The root of trust for the bootstrap service.
 */
extern const unsigned char *bootstrap_crt;
extern const size_t bootstrap_crt_len;

#endif /* not __TEST_CERTS_H__ */
