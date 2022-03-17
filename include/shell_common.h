/*
 * Copyright (c) 2022 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SHELL_COMMON_H
#define SHELL_COMMON_H

#include <shell/shell.h>

/**
 * @brief Helper utility function to print the invalid argument error message
 * with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
cmd_keys_shell_invalid_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the too many arguments error
 * message with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
cmd_keys_shell_too_many_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the missing argument error
 * message with arg_name and return invalid error code.
 *
 * @param       shell     Shell instance
 * @param       arg_name  String to print on the shell console.
 *
 * @return -EINVAL
 */
int
cmd_keys_shell_missing_arg(const struct shell *shell, char *arg_name);

/**
 * @brief Helper utility function to print the error and arg_name and return
 * invalid error code.
 *
 * @param       shell     Shell instance
 * @param       error     String to print on the shell console.
 * @param       rc        Error status code to print on the shell console with
 *                        @p error.
 *
 * @return -EINVAL
 */
int
cmd_keys_shell_rc_code(const struct shell *shell, char *error, int rc);

#endif /* SHELL_COMMON_H */
