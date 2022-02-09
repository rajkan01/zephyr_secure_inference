#!/usr/bin/env python3
#
# Copyright (c) 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0

from cose.messages import CoseMessage
from cose.keys import CoseKey
from cose.keys.curves import P256
from cose.keys.keyparam import KpKty, KpKeyOps, EC2KpX, EC2KpY, EC2KpCurve
from cose.keys.keytype import KtyEC2
from cose.keys.keyops import VerifyOp
import argparse
import cbor2
import struct

supported_action_type = ["COSE_SIGN1_VERIFY", "COSE_DECRYPT_VERIFY"]

EAT_CBOR_LINARO_RANGE_BASE = -80000

# Sample Public key used to verify the sign of cose_encoded_payload
temp_ecdsaPublic = "\
0x4,0x18,0x4d,0xc2,0x5c,0xb,0x32,\
0x2f,0xfb,0xff,0xd,0xdf,0x9b,0x55,\
0x87,0x32,0xf3,0x53,0xf8,0x9a,0xf1,\
0x1b,0x1c,0x89,0x3a,0x8f,0xd5,0xb1,\
0x4d,0x9d,0x5a,0xed,0x8e,0x92,0xea,\
0xda,0x95,0x24,0xdf,0xd4,0xcc,0xcc,\
0x4b,0xe3,0x3c,0x1,0xc8,0x2c,0xb3,\
0xbf,0xb9,0x21,0x68,0x71,0x5a,0x5b,\
0xbc,0xc4,0xa,0x24,0x9d,0x74,0xad,\
0xc,0x68"

# Sample COSE encoded and signed payload
cose_encoded_payload = "\
0xd2,0x84,0x43,0xa1,0x1,0x26,0xa0,0x4b,\
0xa1,0x3a,0x0,0x1,0x38,0x7f,0x44,0x1f,\
0x85,0xab,0x3f,0x58,0x40,0xb7,0x61,0x7c,\
0x38,0x29,0x4b,0xe,0x78,0xbf,0x92,0xb5,\
0x93,0x74,0x9c,0x6c,0x40,0x72,0x13,0x71,\
0xb0,0x6a,0x8a,0x2,0x49,0x4f,0xa4,0xad,\
0x7b,0x15,0x8,0x10,0x4a,0x37,0xc6,0x26,\
0x17,0x31,0xee,0xcf,0x60,0x89,0xa7,0xfc,\
0x46,0x71,0xfd,0x6e,0xe1,0x63,0xe5,0x13,\
0x33,0xcb,0x57,0x2f,0x7e,0x75,0x75,0x1a,\
0x25,0xc1,0xd2,0x75,0xd6"


def split_list(a_list):
    half = len(a_list) // 2
    temp_list = a_list[1:]
    return temp_list[:half], temp_list[half:]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a", "--action", type=str, help="Supported action types COSE_SIGN1_VERIFY, COSE_DECRYPT_VERIFY"
    )
    parser.add_argument(
        "-p", "--payload",
        type=str,
        default=cose_encoded_payload,
        help="COSE encoded and signed payload",
    )
    parser.add_argument(
        "-k", "--publickey",
        type=str,
        default=temp_ecdsaPublic,
        help="Public key to verify the signed payload",
    )

    return parser.parse_args()


def cbor_decode_infer_payload(cbor_enc_payload):
    # Get the inference value from the passed cbor encoded
    # payload in the Map major type.
    decode = cbor2.loads(cbor_enc_payload)
    x = struct.unpack("f", decode[EAT_CBOR_LINARO_RANGE_BASE])
    return x


def cose_verify_sign1(payload, pk):
    # Verify the signature on the passed cose encode payload and
    # retrieve the inference value.
    cose_payload = [int(item, 16) for item in payload.split(",")]
    public_key = [int(item, 16) for item in pk.split(",")]
    x, y = split_list(public_key)
    cose_key = {
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        KpKeyOps: [VerifyOp],
        EC2KpX: bytes(x),
        EC2KpY: bytes(y),
    }

    cose_key = CoseKey.from_dict(cose_key)

    # Decode the payload
    decoded = CoseMessage.decode(bytearray(cose_payload))

    decoded.key = cose_key
    # Verify the signature
    if decoded.verify_signature():
        print("Successfully verified the signature")

    print("Payload::", bytearray(decoded.payload).hex())
    infer_value = cbor_decode_infer_payload(decoded.payload)
    print("Inference value from the payload::", infer_value)


def main():
    args = parse_args()
    if args.action in supported_action_type:
        if args.action == "COSE_SIGN1_VERIFY":
            cose_verify_sign1(args.payload, args.publickey)
        elif args.action == "COSE_DECRYPT_VERIFY":
            print("Decrypt is not supported")
    else:
        print(args.action, "is not supported" )
        print("Supported action type :", supported_action_type)


if __name__ == "__main__":
    main()
