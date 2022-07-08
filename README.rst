.. _tfm_secure_inference:

TF-M Confidential AI Project
############################

.. image:: https://github.com/Linaro/zephyr_secure_inference/blob/main/docs/arch-overview.flat.png?raw=true
  :alt: Confidential AI Architecture Overview

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

Required Setup
**************

This sample assumes you have already cloned zephyr locally. You will need to
use a specific commit of zephyr to be sure that certain assumptions in this
sample are met:

- ``6f108d7f76bb7f21c8b8c62a9cee1aabdf86659f``

Run these commands to checkout the expected commit hash, and apply a required
patch to TF-M, allowing us to enable CPP support in the TF-M build system. This
patch also modifies relevant target's flash layout(s) to increase flash
allocation for the secure image(s), where required:

.. code-block:: console

   $ cd path/to/zephyrproject/zephyr
   $ source zephyr-env.sh
   $ git checkout 6f108d7f76bb7f21c8b8c62a9cee1aabdf86659f
   $ west update
   $ cd ../modules/tee/tf-m/trusted-firmware-m
   $ git apply <sample-path>/patch/tfm.patch

Building and Running
********************

This app is built as a Zephyr application, and can be built with the west
command.  There are a few config options that need to be set in order for it to
build successfully.  A sample configuration could be:

Build without networking support:

.. code-block:: console

   $ west build -p auto -b mps2_an521_ns -t run

Build with networking support and QEMU user mode for networking:

.. code-block:: console

   $ west build -p auto -b mps2_an521_ns -t run -- \
       -DOVERLAY_CONFIG="overlay-smsc911x.conf overlay-network.conf" \
       -DCONFIG_NET_QEMU_USER=y \
       -DCONFIG_BOOTSTRAP_SERVER_HOST=\"hostname.domain.com\"

.. note::

   ``DCONFIG_BOOTSTRAP_SERVER_HOST`` should point to the domain name where
   the bootstrap server is located. This may be a proper domain, or the
   output of the `hostname` command, depending on how the bootstrap server
   was configured. See https://github.com/microbuilder/linaroca
   for details.

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
   [HUK DERIV SERV] tfm_huk_deriv_ec_key()::382 Successfully derived the key for HUK_COSE
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

Compilation fails with ``ca_crt.txt: No such file or directory``
===============================================================

If you are building with networking support, some files from the LITE
Bootstrap Server (https://github.com/microbuilder/linaroca) are required to
be copied into your sample application so that it can generate X.509
certificates, and communicate with the MQTT Broker that the bootstrap server
describes.

Make sure you've run the following scripts in the bootstrap server:

- ``setup-ca.sh``
- ``setup-bootstrap.sh``

And then copy the following files:

.. code-block::

   <bootstrap>/certs/bootstrap_crt.txt -> src/bootstrap_crt.txt
   <bootstrap>/certs/bootstrap_key.txt -> src/bootstrap_key.txt
   <bootstrap>/certs/ca_crt.txt        -> src/ca_crt.txt

Before running this sample, be sure that you also execute the
``run-server.sh`` script to start the LITE bootstrap server.

If everything is configured correctly you can run the ``keys ca 5001`` shell
command to get an X.509 certificate for the client TLS key:

.. code-block::

   uart:~$ keys ca 5001
   argc: 2
   [00:00:25.904,000] <inf> app: uuid: d74696ad-cb3b-4275-b74a-c346ffe71ea9

   Generating X.509 CSR for 'Device Client TLS' key:
   Subject: O=Linaro,CN=d74696ad-cb3b-4275-b74a-c346ffe71ea9,OU=Device Client TLS
   [HUK DERIV SERV] Verified ASN.1 tag and length of the payload
   [HUK DERIV SERV] Key id: 0x5001
   cert starts at 0x2e2 into buffer
   [00:00:26.787,000] <inf> app: Got DNS for linaroca
   [00:00:27.346,000] <inf> app: All data received 591 bytes
   [00:00:27.346,000] <inf> app: Response to req
   [00:00:27.347,000] <inf> app: Status OK
   [00:00:27.348,000] <inf> app: Result: 3
   [00:00:27.349,000] <inf> app: cert: 461 bytes
   ...
   [00:00:27.403,000] <inf> app: Request result: 390
   [00:00:27.408,000] <inf> app: Close: 0

And you should see the following log message for the bootstrap server:

.. code-block::

   $ ./run-server.sh 
   Using config file: /Users/xyz/linaroca/.linaroca.toml
   Starting mTLS TCP server on MBP2021.lan:8443
   Starting CA server on https://MBP2021.lan:1443
   2022/05/23 12:47:07 Received CSR: CN=d74696ad-cb3b-4275-b74a-c346ffe71ea9,OU=Device Client TLS,O=Linaro

How to disable TrustZone on the ``B-U585I-IOT02A``?
===================================================

If you have flashed a sample to the B-U585I-IOT02A board that enables TrustZone,
you will need to disable it before you can flash and run a new non-TrustZone
sample on the board.

To disable TrustZone on the `B-U585I-IOT02A <https://www.st.com/en/evaluation-tools/b-u585i-iot02a.html>`_
board, i.e. set TZEN bit from 1 to 0 in the User Configuration register, it's
necessary to change AT THE SAME TIME the TZEN and the RDP bits.

Hence, TZEN needs to get set from 1 to 0 and RDP, AT THE SAME TIME, needs to get
set from DC to AA (step 3 below).

This is docummented in the `AN5347, in section 9, "TrustZone deactivation" <https://www.st.com/resource/en/application_note/dm00625692-stm32l5-series-trustzone-features-stmicroelectronics.pdf>`_.

However it happens that the RDP bit is probably not set to DC yet, so first you
need to set it to DC (step 2).

Finally you need to set the "Write Protection 1 & 2" bytes properly, otherwise
some memory regions won't be erasable and mass erase will fail (step 4).

The following command sequence will fully deactivate TZ:

Step 1:

Ensure U23 BOOT0 switch is set to 1 (switch is on the left, assuming you read
"BOOT0" silkscreen label from left to right). You need to press "Reset" (B2 RST
switch) after changing the switch to make the change effective.

Step 2:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob rdp=0xDC

Step 3:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -tzenreg

Step 4:

.. code-block:: console

   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1a_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1a_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1b_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp1b_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2a_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2a_pend=0x0
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2b_pstrt=0x7f
   $ ./STM32_Programmer_CLI -c port=/dev/ttyACM0 -ob wrp2b_pend=0x0
