# Cryptography Pen-Testing Project (pwn.college)

This project focuses on penetration testing in cryptographic systems, leveraging tools like:

**Pwntools** – for automating input sending and output retrieval.
**cURL** – for extracting data from databases.
**Mathematical operations** – such as XOR bitwise manipulation on Many-time Pad AES.

## Objectives

The main goal is to gain hands-on experience with common encryption and decryption algorithms, as demonstrated in pwn.college Cryptography Course and various CTF challenges (e.g., picoCTF). The project also explores real-world applications by integrating cryptographic attacks with web exploitation techniques (e.g., SQL injection).

## Cryptographic Algorithms Covered

Encoding & Simple Ciphers: XOR, Hex, Base64
Symmetric Encryption: One-time Pad, Many-time Pad AES (ECB, CBC, CPA, POA)
Asymmetric Encryption: Diffie-Hellman Key Exchange (DHKE → AES), RSA
Hashing & Integrity: SHA (various versions)

## Additional Topics

Performing TLS handshakes (using Pwntools) with self-signed root certificates and private keys.
Deriving AES-128 keys from exchanged secrets in secure communications.
