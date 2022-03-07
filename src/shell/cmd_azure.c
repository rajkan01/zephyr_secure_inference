/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <azure.h>
#include <shell/shell.h>
#include <logging/log.h>

LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_AZURE_SHELL_CMD_SUPPORT

static int
cmd_azure_status(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "TODO: Implement meaningful status");

	return 0;
}

static int
cmd_azure_start(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Starting Azure work thread");
	start_azure_service();

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_cmd_azure,
	/* Status */
	SHELL_CMD(status, NULL, "Azure connection status", cmd_azure_status),
	SHELL_CMD(start, NULL, "Start Azure client", cmd_azure_start),
	SHELL_SUBCMD_SET_END
	);

SHELL_CMD_REGISTER(azure, &sub_cmd_azure, "Azure commands", NULL);

#endif /* CONFIG_AZURE_SHELL_CMD_SUPPORT */
