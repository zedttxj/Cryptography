# Half-Onion PKI — Lightweight Auth over WebSocket
A secure, scoped, and decentralized identity protocol inspired by the principles of onion routing — but halfway there. 🔐🧅
## 🧅 Half-Onion PKI — Real-Time Auth over WebSocket
Half-Onion PKI is a minimalist Public Key Infrastructure system built for lightweight WebSocket identity verification. Designed with speed and security in mind, it issues short-lived RSA certs scoped to ephemeral rooms, enabling real-time mutual authentication without centralized logins.

## 🧠 Key Concepts
- Local CA with RSA 2048 key signing

- Room-bound identity: certs tied to roomId

- Nonce-based handshake to prove key ownership

- Optional manual cert approval or relay-triggered flow

- Works as a decentralized WebSocket trust layer

## 🚀 Why “Half-Onion”?
Because it wraps identity in one cryptographic layer — not a full Tor node, but just enough for:

- Peer-to-peer service mesh

- Secure relays

- Sandbox authentication for experimental backbones

## 📁 Structure
```
/ca           # Certificate Authority logic
/client       # Client cert requester + nonce responder
/relay        # (Optional) room monitor and notifier
/shared       # Key generation and cert verification utils
/test         # Authenticated client-to-client demo
```
## 🔒 Security Features
- RSA-2048 public/private keypair generation

- SHA-256 signature signing/verification

- Cert expiry enforcement (default: 30s)

- Manual or semi-automatic room trust

## 💡 Future Ideas
- Mutual handshake (bi-directional nonce auth)

- Encrypted messaging after trust

- Time-limited room access via cert expiration

- Relay federation with shared trust anchor

>🧅 Because not everything needs a full onion.
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
