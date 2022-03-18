/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_certs.h"

static const unsigned char raw_ca_certificate[] = {
#include "digicert.cer"
};
const unsigned char *ca_certificate = raw_ca_certificate;
const size_t ca_certificate_len = sizeof(raw_ca_certificate);

/* The device certificate should be ASCII in PEM format.  It should
 * start with "-----BEGIN CERTIFICATE-----\r\n", and can easily be
 * made by surrounding each line with quotes, and adding "\r\n" to the
 * end.
 */
static const char raw_device_crt[] =
#include "device_crt.txt"
;
const char *device_crt = raw_device_crt;
const size_t device_crt_len = sizeof(raw_device_crt);

/* The device private key should be the output of the binary
 * DER-format key file in hex.  This can be generated, for example,
 * with `xxd -i`.
 */
static const unsigned char raw_device_key[] = {
#include "device_key.txt"
};
const unsigned char *device_key = raw_device_key;
const size_t device_key_len = sizeof(raw_device_key);

/* The setup-ca.sh script in the linarca repo should create this file.
 */
static const unsigned char raw_bootstrap_crt = {
#include "ca_crt.txt"
};
const unsigned char *bootstrap_crt = raw_bootstrap_crt;
const size_t bootstrap_crt_len = sizeof(raw_bootstrap_crt);
