# 🔐 Secure WebSocket Identity Protocol with Local CA
This project is a self-contained Public Key Infrastructure (PKI) system built for real-time identity verification over WebSocket. It simulates a lightweight yet secure authentication mechanism suitable for peer-to-peer networks, relays, or service backbones.

## 🧩 Components
- Local CA: Issues short-lived RSA certificates signed with SHA-256, optionally with manual approval

- Client: Requests cert, joins a room, and performs nonce-based authentication with peers

- Room-based trust model: Clients are assigned scoped roomIds signed into their certs

- Relay (optional): Detects new rooms and notifies CA to prepare for signing

## 🔒 Security Features
- Challenge-response handshake using random nonces

- Certificate expiration and verification using crypto.createVerify()

- Manual room approval flow for high-trust cert control

- No central login: trust is proven cryptographically

## 💡 Uses
- Lightweight identity verification for WebRTC / P2P apps

- Secure signaling layer for collaborative tools or private relays

- Educational PKI implementation for real-world cryptography


# Cryptography Pen-Testing Project (pwn.college)
This project focuses on **penetration testing in cryptographic systems**, using a variety of tools:

- **Pwntools**: for automating input sending and output retrieval.  
- **cURL**: for extracting data from databases.  
- **Mathematical operations**: like XOR bitwise manipulation, applied to Many-time Pad AES.

## Acknowledgement
I finished all of these modules from **pwn.college**, but will only demonstrate few examples here. You can check my profile on the [website](https://pwn.college/hacker/1o1).
## Objectives

The main goal is to gain hands-on experience with encryption and decryption algorithms, as demonstrated in the [pwn.college Cryptography Course](https://pwn.college/cse365-f2024/cryptography/) and various **CTF challenges** (e.g., picoCTF). The project also explores **real-world applications** by combining cryptographic attacks with web exploitation techniques (e.g., SQL injection).

## Cryptographic Algorithms Covered

- **Encoding & Simple Ciphers**: XOR, Hex, Base64  
- **Symmetric Encryption**: One-time Pad, Many-time Pad AES (ECB, CBC, CPA, POA), Diffie-Hellman Key Exchange (DHKE → AES)
- **Asymmetric Encryption**: RSA  
- **Hashing & Integrity**: SHA (various versions)

## Additional Topics

- Performing **TLS handshakes** (using Pwntools) with self-signed root certificates and private keys.  
- Deriving **AES-128 keys** from exchanged secrets in secure communications.
