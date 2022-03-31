.. _tfm_secure_inference:

TF-M Confidential AI Project
############################

Dependencies
************

This sample is based off the following Zephyr commit:
``ca842acdd7a3e9f84125a19ce89034a55c723d29``

TensorFlow Lite Micro also requires us to enable CPP support in TF-M, which
can be done with the following patch on top of TF-M commit
``b90420a2ffbf7d1329716508f1d3f9f880bc865b``

.. code-block::

   diff --git a/CMakeLists.txt b/CMakeLists.txt
   index 1e119997..395330ad 100644
   --- a/CMakeLists.txt
   +++ b/CMakeLists.txt
   @@ -65,7 +65,7 @@ endif()
   include(${TFM_TOOLCHAIN_FILE})
   set(CMAKE_PROJECT_INCLUDE_BEFORE ${CMAKE_SOURCE_DIR}/cmake/disable_compiler_detection.cmake)
   
   -project("Trusted Firmware M" VERSION ${TFM_VERSION} LANGUAGES C ASM)
   +project("Trusted Firmware M" VERSION ${TFM_VERSION} LANGUAGES C CXX ASM)
   tfm_toolchain_reload_compiler()
   
   # Synchronise the install path variables. If CMAKE_INSTALL_PREFIX is manually
   diff --git a/cmake/disable_compiler_detection.cmake b/cmake/disable_compiler_detection.cmake
   index ebafca06..215221a2 100644
   --- a/cmake/disable_compiler_detection.cmake
   +++ b/cmake/disable_compiler_detection.cmake
   @@ -7,3 +7,4 @@
   
   #Stop cmake running compiler tests.
   set (CMAKE_C_COMPILER_FORCED true)
   +set (CMAKE_CXX_COMPILER_FORCED true)
   diff --git a/platform/ext/common/gcc/tfm_common_s.ld b/platform/ext/common/gcc/tfm_common_s.ld
   index d3aada37..8257e2d3 100644
   --- a/platform/ext/common/gcc/tfm_common_s.ld
   +++ b/platform/ext/common/gcc/tfm_common_s.ld
   @@ -183,7 +183,7 @@ SECTIONS
      Image$$ER_CODE_SRAM$$Limit = ADDR(.ER_CODE_SRAM) + SIZEOF(.ER_CODE_SRAM);
   #endif
   
   -#if TFM_LVL != 1
   +/* #if TFM_LVL != 1 */
      .ARM.extab :
      {
            *(.ARM.extab* .gnu.linkonce.armextab.*)
   @@ -196,7 +196,7 @@ SECTIONS
      } > FLASH
      __exidx_end = .;
   
   -#endif /* TFM_LVL != 1 */
   +/* #endif */
   
      .ER_TFM_CODE : ALIGN(4)
      {
   diff --git a/platform/ext/target/stm/common/scripts/postbuild.sh b/platform/ext/target/stm/common/scripts/postbuild.sh
   index 9f7a3734..5fca2f05 100644
   --- a/platform/ext/target/stm/common/scripts/postbuild.sh
   +++ b/platform/ext/target/stm/common/scripts/postbuild.sh
   @@ -16,7 +16,11 @@
   #  ******************************************************************************
   # arg1 is optional, it fixes compiler full path if present
   # Absolute path to this script
   +if [[ "$OSTYPE" == "darwin"* ]]; then
   +SCRIPT=$(greadlink -f $0)
   +else
   SCRIPT=$(readlink -f $0)
   +fi
   # Absolute path this script
   projectdir=`dirname $SCRIPT`
   source $projectdir/preprocess.sh
   diff --git a/toolchain_GNUARM.cmake b/toolchain_GNUARM.cmake
   index 9cb741c0..ca1e596d 100644
   --- a/toolchain_GNUARM.cmake
   +++ b/toolchain_GNUARM.cmake
   @@ -14,11 +14,16 @@ endif()
   set(CMAKE_SYSTEM_NAME Generic)
   
   find_program(CMAKE_C_COMPILER ${CROSS_COMPILE}-gcc)
   +find_program(CMAKE_CXX_COMPILER ${CROSS_COMPILE}-g++)
   
   if(CMAKE_C_COMPILER STREQUAL "CMAKE_C_COMPILER-NOTFOUND")
      message(FATAL_ERROR "Could not find compiler: '${CROSS_COMPILE}-gcc'")
   endif()
   
   +if(CMAKE_CXX_COMPILER STREQUAL "CMAKE_CXX_COMPILER-NOTFOUND")
   +    message(FATAL_ERROR "Could not find compiler: '${CROSS_COMPILE}-g++'")
   +endif()
   +
   set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
   
   set(LINKER_VENEER_OUTPUT_FLAG -Wl,--cmse-implib,--out-implib=)
   @@ -47,9 +52,13 @@ macro(tfm_toolchain_reset_compiler_flags)
            -funsigned-char
            -mthumb
            -nostdlib
   -        -std=c99
   +        $<$<COMPILE_LANGUAGE:C>:-std=c99>
            $<$<OR:$<BOOL:${TFM_DEBUG_SYMBOLS}>,$<BOOL:${TFM_CODE_COVERAGE}>>:-g>
      )
   +
   +    add_compile_options(
   +        $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>
   +    )
   endmacro()
   
   macro(tfm_toolchain_reset_linker_flags)
   @@ -123,6 +132,7 @@ macro(tfm_toolchain_reload_compiler)
      endif()
   
      unset(CMAKE_C_FLAGS_INIT)
   +    unset(CMAKE_CXX_FLAGS_INIT)
      unset(CMAKE_ASM_FLAGS_INIT)
   
      if (DEFINED TFM_SYSTEM_PROCESSOR)
   @@ -138,6 +148,7 @@ macro(tfm_toolchain_reload_compiler)
      endif()
   
      set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS_INIT})
   +    set(CMAKE_CXX_FLAGS ${CMAKE_C_FLAGS_INIT})
      set(CMAKE_ASM_FLAGS ${CMAKE_ASM_FLAGS_INIT})
   
      set(BL2_COMPILER_CP_FLAG -mfloat-abi=soft)

Overview
********

This Zephyr project provides a complete secure (S) plus non-secure (NS)
solution for execution of an inference engine in the secure processing
environment, as well as end-to-end processing of inference outputs.

Outputs from the inference engine are encoded as CBOR payloads, with COSE used
to  enable optional signing and encryption of the data.

Custom secure services are included in the sample in the
``tfm_secure_inference_partitions`` folder:

- TF-M HUK Key Derivation: UUID and key derivation from the HUK
- TFLM Service: TensorFlow Lite Micro inference engine and model execution

These secure services are added to TF-M as part of the secure build process
that takes place before the NS Zephyr application is built, and are
available to the NS environment based on the access-rights specified in
the service definition files.

Inference Engine(s)
===================

This sample currently uses TensorFlow Lite Micro (TFLM) as the inference engine,
with a simple sine-wave model.

This will be extended to support microTVM in the future with the same sine-wave
model in the near future, in addition to more complex AI/ML models.

You can interact with the sine wave model from the NS side via the ``infer``
shell command.

Key management
==============

Certain operations like signing or encrypting the COSE-encoded inference engine
outputs require the use of keys, and X.509 certificates for these keys.

All keys used in this project are derived at startup from the Hardware Unique
Key (HUK), meaning that they are device-bound (i.e. explicity tied to a
specific instance of an SoC), storage-free (meaning they can't be retrieved
by dumping flash memory or firmware analysis), and repeatable across firmware
updates.

X.509 certificates generated for these keys are associated with a UUID, which
is also derived from the HUK. This derived UUID allows us to uniquely and
consistently identify a single SoC or embedded device.

The following EC keys are currently generated:

- Device Client TLS key (secp256r1)
- Device COSE SIGN (secp256r1 with SHA-256 digest)
- Device COSE ENCRYPT (secp256r14, ECDH ES w/concat KDF, AES key wrap, 256 bit keys)

The non-secure processing environment exposes a ``keys`` shell command that can
be used to retrieve the public key component of the above private keys, as well
as generate a certificate signing request (CSR) for a specific key.

Building and Running
********************

On Target
=========

Refer to :ref:`tfm_ipc` for detailed instructions.

On QEMU:
========

Refer to :ref:`tfm_ipc` for detailed instructions.

Sample Output
=============

   .. code-block:: console

      [INF] Beginning TF-M provisioning
      [WRN] TFM_DUMMY_PROVISIONING is not suitable for production! This device is NOT SECURE
      [Sec Thread] Secure image initializing!
      TF-M FP mode: Software
      Booting TFM v1.5.0
      Creating an empty ITS flash layout.
      Creating an empty PS flash layout.
      [TFLM service] Successfully derived the key from HUK for CLIENT_TLS
      [TFLM service] Successfully derived the key from HUK for C_SIGN
      [TFLM service] Successfully derived the key from HUK for C_ENCRYPT
      [TFLM service] TFLM initalisation completed
      *** Booting Zephyr OS build v2.7.99-2785-ge3c585041afe  ***
      [UUID service] Generated UUID: 359187E6-3D53-F7E9-3DDB-07C102520937

               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
      00000000 04 64 79 7F 68 E0 CE E7 97 BA 11 71 AB 3E 36 98 .dy.h......q.>6.
      00000010 24 9B 96 E7 71 CF D1 E3 E1 4E 4A BB 58 F2 0A 68 $...q....NJ.X..h
      00000020 AD BD 99 17 99 2E 9C A9 B5 AF 86 11 DE D5 28 F9 ..............(.
      00000030 5E 50 8C 5C 90 F0 B7 09 7F 55 0C 7E 04 67 84 FC ^P.\.....U.~.g..
      00000040 36                                              6

      [TFLM service] Starting secure inferencing...
      [TFLM service] Starting CBOR encoding and COSE signing...

               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
      00000000 D2 84 43 A1 01 26 A0 4B A1 3A 00 01 38 7F 44 2C ..C..&.K.:..8.D,
      00000010 CE 8A 3C 58 40 B7 61 7C 38 29 4B 0E 78 BF 92 B5 ..<X@.a|8)K.x...
      00000020 93 74 9C 6C 40 72 13 71 B0 6A 8A 02 49 4F A4 AD .t.l@r.q.j..IO..
      00000030 7B 15 08 10 4A 75 98 37 9C 3D 31 3D ED 10 EC 60 {...Ju.7.=1=...`
      00000040 2E 45 FE 20 2B F3 A5 F3 F8 65 0A E0 2A 68 CC 7A .E. +....e..*h.z
      00000050 3E A5 A2 48 9D                                  >..H.

      Model: Sine of 1 deg is: 0.016944       C Mathlib: Sine of 1 deg is: 0.017452   Deviation: 0.000508

Common Problems
***************

Why are my derived keys values and UUID always the same?
=========================================================

TF-M defines a hard-coded HUK value for the mps2 and mps3 platforms, meaning
that every instance of this sample run on these platforms will derive the same
key values.

This project defines an optional ``HUK_DERIV_SEED_EXTRA`` value in the secure
parition that can be used to provide an additional label component for key
derivation, enabling key diversity when testing on emulated platforms.
    
A KConfig wrapper for this variable is also added via the
``DCONFIG_SECURE_INFER_HUK_DERIV_SEED_EXTRA`` config flag to facilitate passing
the seed from Zephyr's build system up to the TF-M build system.

The seed value must be less than 16 characters in size!

It can be defined at compile time with west via:

::

   $ west build -p -b mps2_an521_ns -t run -- \
     -DCONFIG_SECURE_INFER_HUK_DERIV_SEED_EXTRA=\"123456789012345\"
