/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <ctype.h>
#include <shell/shell.h>
#include "shell/cmd_key_mgmt.h"

#if CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT

static int
psa_shell_invalid_arg(const struct shell *shell, char *arg_name)
{
	shell_print(shell, "Error: invalid argument \"%s\"\n", arg_name);

	return -EINVAL;
}

static int
psa_shell_cmd_version(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "%s", "1.0.0");

	return 0;
}

static int
psa_shell_get_uuid(const struct shell *shell, size_t argc, char **argv)
{
	unsigned char uuid[37];
	psa_status_t status;

	status = psa_get_uuid(uuid, sizeof(uuid));
	if (status != 0) {
		return -EINVAL;
	}
	shell_print(shell, "%s", uuid);
	return 0;
}


/* Subcommand array for "info" (level 1). */
SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_info,
    /* 'version' command handler. */
	SHELL_CMD(version, NULL, "app version", psa_shell_cmd_version),
	/* 'UUID' command handler. */
	SHELL_CMD(uuid, NULL, "Device uuid", psa_shell_get_uuid),
    /* Array terminator. */
	SHELL_SUBCMD_SET_END
);

/* Root command "info" (level 0). */
SHELL_CMD_REGISTER(info, &sub_cmd_info, "Device information", NULL);

#endif	/* CONFIG_SECURE_INFER_SHELL_CMD_SUPPORT */
