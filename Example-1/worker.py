#!/opt/pwn.college/python

from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = b64decode(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "please give me the flag, kind worker process!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
