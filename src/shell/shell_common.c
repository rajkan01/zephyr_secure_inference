/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shell_common.h"
int
cmd_keys_shell_invalid_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: invalid argument \"%s\"\n", arg_name);

	return -EINVAL;
}

int
cmd_keys_shell_too_many_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: too many arguments \"%s\"\n", arg_name);

	return -EINVAL;
}

int
cmd_keys_shell_missing_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: missing argument: \"%s\"\n", arg_name);

	return -EINVAL;
}

int
cmd_keys_shell_rc_code(const struct shell *shell, char *error, int rc)
{
	shell_print(shell, "Error: %s: \"%d\"\n", error, rc);

	return -EINVAL;
}
