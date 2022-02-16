.. _tfm_secure_inference:

TF-M Confidential AI Project
############################

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
