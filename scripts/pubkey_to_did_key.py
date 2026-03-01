#!/usr/bin/env python3
"""
Convert an OpenSSH Ed25519 public key to a did:key identifier.

Usage: python3 pubkey_to_did_key.py "<openssh-pub-key-line>"
Example: python3 pubkey_to_did_key.py "ssh-ed25519 AAAAC3Nz... comment"
"""
import base64
import sys

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    result = ''
    while n:
        n, rem = divmod(n, 58)
        result = ALPHABET[rem] + result
    pad = next((i for i, b in enumerate(data) if b != 0), len(data))
    return ALPHABET[0] * pad + result


def openssh_pub_to_did_key(openssh_pub: str) -> str:
    # OpenSSH wire format: [4-byte len][type][4-byte len][key bytes]
    key_data = base64.b64decode(openssh_pub.strip().split()[1])
    offset = 4 + int.from_bytes(key_data[0:4], 'big')  # skip "ssh-ed25519"
    key_len = int.from_bytes(key_data[offset:offset + 4], 'big')
    raw_key = key_data[offset + 4:offset + 4 + key_len]

    # did:key encoding: multicodec Ed25519 prefix (0xED 0x01) + raw pubkey
    prefixed = bytes([0xED, 0x01]) + raw_key
    return 'did:key:z' + base58_encode(prefixed)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: pubkey_to_did_key.py '<openssh-pub-key>'", file=sys.stderr)
        sys.exit(1)
    print(openssh_pub_to_did_key(sys.argv[1]))
