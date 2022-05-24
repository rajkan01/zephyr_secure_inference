/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __LOCAL_KEY_H__
#define __LOCAL_KEY_H__

#include <key_mgmt.h>

/**
 * @brief Convert the given key context into a local key.
 *
 * The given key is converted from a secure-only to a locally (non-secure)
 * available key.  When this is finished, the #key_id field will be replaced
 * with a new key (derived from the secure-side key).  In addition, the
 * #local_bytes field will be filled with the local representation of this key.
 *
 * @param ctx  The key context to modify.
 * @return int Return a negative errno if this key could not be converted.
 */
int lkey_convert(struct km_key_context *ctx);

#endif /* not __LOCAL_KEY_H__ */
