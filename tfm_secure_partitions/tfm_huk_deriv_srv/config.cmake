#-------------------------------------------------------------------------------
# Copyright (c) 2022, Linaro. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------

# The MPS2/MPS3 boards in TF-M use a hard-coded value for the HUK, meaning
# every HUK-derived key value will be identical. HUK_DERIV_SEED_EXTRA appends
# the supplied string to the label used for key derivation, enabling key
# diversity during testing with MPSx boards in QEMU. It can be set at compile
# time via '-DHUK_DERIV_SEED_EXTRA=value'.
set(HUK_DERIV_SEED_EXTRA  "" CACHE STRING "Additional key derivation seed value.")

# To avoid buffer issues, the string must be <= 15 characters
string(LENGTH "${HUK_DERIV_SEED_EXTRA}" size)
if(size GREATER 15)
  message(FATAL_ERROR "HUK_DERIV_SEED_EXTRA must be less than 16 characters")
endif()

# Display seed value if available
string(COMPARE NOTEQUAL "${HUK_DERIV_SEED_EXTRA}" "" notnull)
if(notnull)
  message("-- HUK_DERIV_SEED_EXTRA is set to ${HUK_DERIV_SEED_EXTRA}")
endif()

# Make the seed value available in the C project
add_compile_definitions(HUK_DERIV_SEED_EXTRA="${HUK_DERIV_SEED_EXTRA}")
