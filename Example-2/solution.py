#!/opt/pwn.college/python

import sys
import string
import random
import pathlib
import base64
import json
import textwrap

from pwn import *
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad




def show(name, value, *, b64=True):
    print(f"{name}: {value}")


def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex_block(name, value, byte_block_size=16):
    value_to_show = ""

    for i in range(0, len(value), byte_block_size):
        value_to_show += f"{value[i:i+byte_block_size].hex()}"
        value_to_show += " "
    show(f"{name} (hex)", value_to_show)


def show_hex(name, value):
    show(name, hex(value))


def input_(name):
    try:
        return input(f"{name}: ")
    except (KeyboardInterrupt, EOFError):
        print()
        exit(0)


def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)


def input_hex(name):
    data = input_(name)
    try:
        return int(data, 16)
    except Exception:
        print(f"Failed to decode hex input: {data!r}", file=sys.stderr)
        exit(1)

def main():
    """
    In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server.
    You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key.
    The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange.
    The server must complete the key exchange, and derive an AES-128 key from the exchanged secret.
    Then, using the encrypted channel, the server must supply the requested user certificate, signed by root.
    Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.
    """

    r = process("/challenge/run")

    # 2048-bit MODP Group from RFC3526
    p = int.from_bytes(bytes.fromhex(
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
        "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
    ), "big")
    g = 2

    #show_hex("p", p)
    #show_hex("g", g)

    root_key = RSA.generate(2048)

    #show_hex("root key d", root_key.d)
    r.recvuntil(b"root key d: ")
    root_key_d = r.recvline()[:-1] # Cut of the last character, which is "\n"
    root_key_d = int(root_key_d, 16) # Convert hex string into in

    #root_certificate = {
    #    "name": "root",
    #    "key": {
    #        "e": root_key.e,
    #        "n": root_key.n,
    #    },
    #    "signer": "root",
    #}

    #root_trusted_certificates = {
    #    "root": root_certificate,
    #}

    #root_certificate_data = json.dumps(root_certificate).encode()
    #root_certificate_hash = SHA256Hash(root_certificate_data).digest()
    #root_certificate_signature = pow(
    #    int.from_bytes(root_certificate_hash, "little"),
    #    root_key.d,
    #    root_key.n
    #).to_bytes(256, "little")

    #show_b64("root certificate", root_certificate_data)
    r.recvuntil(b"root certificate (b64): ")
    root_certificate_data = json.loads(base64.b64decode(r.recvline()[:-1]))
    #show_b64("root certificate signature", root_certificate_signature)
    r.recvuntil(b"root certificate signature (b64): ")
    root_certificate_signature = base64.b64decode(r.recvline()[:-1])

    #name = ''.join(random.choices(string.ascii_lowercase, k=16))
    #show("name", name)
    r.recvuntil(b"name: ")
    name = r.recvline()[:-1]

    #a = getrandbits(2048)
    #A = pow(g, a, p)
    #show_hex("A", A)
    r.recvuntil(b"A: ")
    A = r.recvline()[:-1]
    A = int(A, 16)

    #B = input_hex("B")
    #if not (B > 2**1024):
    #    print("Invalid B value (B <= 2**1024)", file=sys.stderr)
    #    exit(1)
    b = getrandbits(2048)
    B = pow(g, b, p)
    r.sendline(hex(B))

    s = pow(A, b, p)
    key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]
    cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
    cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)

    #def decrypt_input_b64(name):
    #    data = input_b64(name)
    #    try:
    #        return unpad(cipher_decrypt.decrypt(data), cipher_decrypt.block_size)
    #    except ValueError as e:
    #        print(f"{name}: {e}", file=sys.stderr)
    #        exit(1)

    #user_certificate_data = decrypt_input_b64("user certificate")
    #user_certificate_signature = decrypt_input_b64("user certificate signature")
    #user_signature = decrypt_input_b64("user signature")

    def decoy(inp):
        r.sendline(base64.b64encode(cipher_encrypt.encrypt(pad(inp, cipher_encrypt.block_size))))

    from Crypto.Util.number import getPrime, inverse
    p = 0
    q = 0
    n = 0
    while True:
        p = getPrime(512)
        q = getPrime(512)
        n = p*q
        if 2**512 < n < 2**1024:
            break
    phi = (p-1)*(q-1)
    user_key_e = 65537
    #user_key_d = pow(user_key_e, -1, phi)
    user_key_d = inverse(user_key_e, phi)
    user_certificate_data = {
        "name":name.decode(), # convert bytestring into string
        "key": {
            "e":user_key_e,
            "n":n
        },
        "signer":"root"
    }
    decoy(json.dumps(user_certificate_data).encode())
    user_certificate_signature = SHA256Hash(json.dumps(user_certificate_data).encode()).digest()
    user_certificate_signature = pow(
        int.from_bytes(user_certificate_signature, "little"),
        root_key_d,
        root_certificate_data["key"]["n"]
    ).to_bytes(256, "little")
    decoy(user_certificate_signature)
    user_signature = (
        name.ljust(256, b"\0") +
        A.to_bytes(256, "little") +
        B.to_bytes(256, "little")
    )
    user_signature = SHA256Hash(user_signature).digest()
    user_signature = pow(
        int.from_bytes(user_signature, "little"),
        user_key_d,
        n
    ).to_bytes(256, "little")
    decoy(user_signature)
    r.recvuntil(b"secret ciphertext (b64): ")
    cipher_text = r.recvline()[:-1]
    print(unpad(cipher_decrypt.decrypt(base64.b64decode(cipher_text)), cipher_decrypt.block_size))
    exit()


    #try:
    #    user_certificate = json.loads(user_certificate_data)
    #except json.JSONDecodeError:
    #    print("Invalid user certificate", file=sys.stderr)
    #    exit(1)

    #user_name = user_certificate.get("name")
    #if user_name != name:
    #    print(f"Invalid user certificate name: `{user_name}`", file=sys.stderr)
    #    exit(1)

    #user_key = user_certificate.get("key", {})
    #if not (isinstance(user_key.get("e"), int) and isinstance(user_key.get("n"), int)):
    #    print(f"Invalid user certificate key: `{user_key}`", file=sys.stderr)
    #    exit(1)

    #if not (user_key["e"] > 2):
    #    print("Invalid user certificate key e value (e > 2)", file=sys.stderr)
    #    exit(1)

    #if not (2**512 < user_key["n"] < 2**1024):
    #    print("Invalid user certificate key n value (2**512 < n < 2**1024)", file=sys.stderr)
    #    exit(1)

    #user_signer = user_certificate.get("signer")
    #if user_signer not in root_trusted_certificates:
    #    print(f"Untrusted user certificate signer: `{user_signer}`", file=sys.stderr)
    #    exit(1)

    #user_signer_key = root_trusted_certificates[user_signer]["key"]
    #user_certificate_hash = SHA256Hash(user_certificate_data).digest()
    #user_certificate_check = pow(
    #    int.from_bytes(user_certificate_signature, "little"),
    #    user_signer_key["e"],
    #    user_signer_key["n"]
    #).to_bytes(256, "little")[:len(user_certificate_hash)]

    #if user_certificate_check != user_certificate_hash:
    #    print("Untrusted user certificate: invalid signature", file=sys.stderr)
    #    exit(1)

    #user_signature_data = (
    #    name.encode().ljust(256, b"\0") +
    #    A.to_bytes(256, "little") +
    #    B.to_bytes(256, "little")
    #)
    #user_signature_hash = SHA256Hash(user_signature_data).digest()
    #user_signature_check = pow(
    #    int.from_bytes(user_signature, "little"),
    #    user_key["e"],
    #    user_key["n"]
    #).to_bytes(256, "little")[:len(user_signature_hash)]

    #if user_signature_check != user_signature_hash:
    #    print("Untrusted user: invalid signature", file=sys.stderr)
    #    exit(1)

    #ciphertext = cipher_encrypt.encrypt(pad(flag, cipher_encrypt.block_size))
    #show_b64("secret ciphertext", ciphertext)

if __name__=="__main__":
    main()
