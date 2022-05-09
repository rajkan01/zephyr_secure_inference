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
- Device COSE SIGN/ENCRYPT (secp256r1)

The non-secure processing environment exposes a ``keys`` shell command that can
be used to retrieve the public key component of the above private keys, as well
as generate a certificate signing request (CSR) for a specific key.

Building and Running
********************

This app is built as a Zephyr application, and can be built with the west
command.  There are a few config options that need to be set in order for it to
build successfully.  A sample configuration could be:

.. code-block:: console

   $ west build -p always -b mps2_an521_ns . -- \
       -DOVERLAY_CONFIG=overlay-smsc911x.conf \
       -DCONFIG_NET_QEMU_USER=y \
       -DCONFIG_BOOTSTRAP_SERVER_HOST=\"hostname.domain.com\"

On Target
=========

Refer to :ref:`tfm_ipc` for detailed instructions.

On QEMU:
========

Refer to :ref:`tfm_ipc` for detailed instructions.

Sample Output
=============

.. code-block:: console

   $ west build -t run
   -- west build: running target run
   [0/18] Performing build step for 'tfm'
   ninja: no work to do.
   [1/2] To exit from QEMU enter: 'CTRL+a, x'[QEMU] CPU: cortex-m33
   char device redirected to /dev/pts/10 (label hostS0)
   [INF] Beginning TF-M provisioning
   [WRN] TFM_DUMMY_PROVISIONING is not suitable for production! This device is NOT SECURE
   [Sec Thread] Secure image initializing!
   Booting TF-M v1.6.0-RC3+31d4dce6
   Creating an empty ITS flash layout.
   Creating an empty PS flash layout.
   [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_CLIENT_TLS1
   [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_COSE_SIGN1
   [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_COSE_ENCRYPT1
   [UTVM SERVICE] tfm_utvm_service_req_mngr_init()::215 UTVM initalisation completed
   [TFLM SERVICE] tfm_tflm_service_req_mngr_init()::398 initalisation completed
   
   
   uart:~$ *** Booting Zephyr OS build zephyr-v3.0.0-2694-g7cedc5d85e09  ***
   [    2.131000] <inf> app: app_cfg: Creating default config file with UID 0x55CFDA7A
   [    2.133000] <err> app: Invalid argument
   [    2.133000] <err> app: Function: 'cfg_create_data'
   [    2.134000] <err> app: Invalid argument
   [    2.134000] <err> app: Function: 'cfg_load_data'
   [    2.135000] <err> app: Error loading/generating app config data in PS.
   uart:~$ [HUK DERIV SERV] tfm_huk_gen_uuid()::613 Generated UUID: d74696ad-cb3b-4275-b74a-c346ffe71ea9
   [    2.631000] <inf> app: Azure: waiting for network...
   [    7.141000] <inf> app: Azure: Waiting for provisioning...

After waiting for the "Waiting for provisioning" message, the ``keys ca 5001``
command can be used to query the bootstrap server.

.. code-block:: console

   uart:~$ keys ca 5001
   argc: 2
   [    9.288000] <inf> app: uuid: d74696ad-cb3b-4275-b74a-c346ffe71ea9

   Generating X.509 CSR for 'Device Client TLS' key:
   Subject: O=Linaro,CN=d74696ad-cb3b-4275-b74a-c346ffe71ea9,OU=Device Client TLS
   [HUK DERIV SERV] tfm_huk_hash_sign_csr()::503 Verified ASN.1 tag and length of the payload
   [HUK DERIV SERV] tfm_huk_hash_sign_csr()::511 Key id: 0x5001
   cert starts at 0x2e2 into buffer
   [    9.527000] <inf> app: Got DNS for linaroca
   [    9.658000] <inf> app: All data received 595 bytes
   [    9.658000] <inf> app: Response to req
   [    9.658000] <inf> app: Status OK
   [    9.659000] <inf> app: Result: 3
   [    9.659000] <inf> app: cert: 460 bytes
   
            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   00000000 30 82 01 C8 30 82 01 6F A0 03 02 01 02 02 08 16 0...0..o........
   00000010 EB F5 18 21 87 AE 38 30 0A 06 08 2A 86 48 CE 3D ...!..80...*.H.=
   ...
   [    9.725000] <inf> app: provisioned host: davidb-zephyr, port 8883
   [    9.725000] <inf> app: our uuid: d74696ad-cb3b-4275-b74a-c346ffe71ea9
   [    9.726000] <inf> app: Device Topic: devices/d74696ad-cb3b-4275-b74a-c346ffe71ea9/messages/devicebound/#
   [    9.727000] <inf> app: Event Topic: devices/d74696ad-cb3b-4275-b74a-c346ffe71ea9/messages/events/
   [    9.727000] <inf> app: Azure hostname: davidb-zephyr.azure-devices.net
   [    9.728000] <inf> app: Azure port: 8883
   [    9.728000] <inf> app: Azure user: davidb-zephyr.azure-devices.net/d74696ad-cb3b-4275-b74a-c346ffe71ea9
   [    9.729000] <inf> app: Azure: Provisioning available

            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   00000000 30 82 01 C8 30 82 01 6F A0 03 02 01 02 02 08 16 0...0..o........
   00000010 EB F5 18 21 87 AE 38 30 0A 06 08 2A 86 48 CE 3D ...!..80...*.H.=
   ...

Common Problems
***************

Why are my derived keys values and UUID always the same?
=========================================================

TF-M defines a hard-coded HUK value for the mps2 and mps3 platforms, meaning
that every instance of this sample run on these platforms will derive the same
key values.

This project defines an optional ``HUK_DERIV_LABEL_EXTRA`` value in the secure
parition that can be used to provide an additional label component for key
derivation, enabling key diversity when testing on emulated platforms.
    
A KConfig wrapper for this variable is also added via the
``DCONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA`` config flag to facilitate passing
the label from Zephyr's build system up to the TF-M build system.

The label value must be less than 16 characters in size!

It can be defined at compile time with west via:

.. code-block:: console

   $ west build -p -b mps2_an521_ns -t run -- \
     -DCONFIG_SECURE_INFER_HUK_DERIV_LABEL_EXTRA=\"123456789012345\"
