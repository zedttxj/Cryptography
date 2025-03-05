# TLS 2 - [pwn.college](https://pwn.college/cse365-f2024/cryptography/)

## Challenge Overview

In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server.
You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key.
The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange.
The server must complete the key exchange, and derive an AES-128 key from the exchanged secret.
Then, using the encrypted channel, the server must supply the requested user certificate, signed by root.
Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.

## My Approach

My first step is to copy partially the content of the file `run` to my new `.py` file and start analyzing it. A lot of steps are just gonna repeat what's the actual server do.

### 1. Gets all the output from the server

Don't miss any outputs from the server as they're all important except the `flag` file. In this step, we're checking if there's any printing functions are called and mark those into comments (adding "#" in front of the functions). First, I add the line `r = process("/challenge/run")` to run the program (don't forget to import pwn library). Then, we can create input functions after the positions where you have marked unncessary but still can be used for analyzing at the same time:
```
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
    root_key_d = r.recvline()[:-1] # Cut off the last character, which is "\n"
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
```

After that, you can check by printing out all predefined values like this(adding `exit()` to prevent unnecessary logs):
```
print(p, g, name, A, root_key_d)
exit()
```

### 2. Send all necessary values to the program

The program needs some values to process. We gotta send these values to ensure the program run smoothly. As we finish printing those out, we just mark unnecessary comments. Usually, I would mark first, analyze, and then write the code.
Let's start with `B`:
```
#B = input_hex("B")
    #if not (B > 2**1024):
    #    print("Invalid B value (B <= 2**1024)", file=sys.stderr)
    #    exit(1)
    b = getrandbits(2048)
    B = pow(g, b, p)
    r.sendline(hex(B))
```

An "oldie but goodie" algorithm for generating a secret key on a non-secret communication channel is the Diffie-Hellman Key Exchange! DHKE uses the power of mathematics (specifically, Finite Fields) to come up with a key. Let's take it step by step:
- First, Alice and Bob agree on a large prime number p to define their Finite Field (e.g., all further operations occur modulo p: a context where numbers go from 0 to p-1, and then loop around), along with a root g, and exchange them in the open, content to let Eve see them.
- Then, Alice and Bob each generate a secret number (a for Alice's and b for Bob's). These numbers are never shared.
Alice computes A = (g ** a) mod p (g to the a power modulo p) and Bob computes B = (g ** b) mod p. Alice and Bob exchange A and B in the open.
- At this point, Eve will have p, g, A, and B, but will be unable to recover a or b. If it wasn't for the finite field, recovering a and b would be trivial via a logarithm-base-g: log_g(A) == a and log_g(B) == b. However, this does not work in a Finite Field under a modulo because, conceptually, we have no efficient way to determine how many times the g ** a computation "looped around" from p-1 to 0, and this is needed to compute the logarithm. This logarithm-in-a-finite-field problem is called the Discrete Logarithm, and there is no efficient way to solve this without using a quantum computer. Quantum computers' ability to solve this problem is the most immediate thing that makes them so dangerous to cryptography.
- Alice calculates s = (B ** a) mod p, and since B was (g ** b) mod p, this results in s = ((g ** b) ** a) mod p or, applying middle school math, s = (g ** (b*a)) mod p. Bob calculates s = (A ** b) mod p, and since A was (g ** a) mod p, this results in s = (g ** (a*b)) mod p. Since a*b == b*a, the s values computed by both Bob and Alice are equal!
- Eve cannot compute s because Eve lacks a or b. Eve could compute A ** B == g ** a ** g ** b, which reduces to something like g ** (a*(g**b)) and doesn't get Eve any closer to s! Eve could also compute A * B == (g ** a) * (g ** b) == g ** (a+b), but again, this is not the s == g ** (a*b) that Bob and Alice arrived at. Eve is out of luck!
In our case, `s` is equal to `(B ** a) mod p` since we only get `A` from the input above. Similar to the server `run`, we will use hash digest of `s` as a key and AES_CBC as an encryption and a decryption method to exchange information.
Using both hash digest and AES_CBC symmetric encryption method is very secure. The attacker only has 50% for the `2 ** 128`-th try to guess the right key by generating hash collision or 100%  and would takes, generally, `len(content)*256` tries to send the malicious `content` to the victim. The measure can be prevented by setting expiration date for the key or automatically revoke the old key and exchange the new key after a period of time.
That seems secure! However, Eve can stand in the middle and establish connections with both Alice and Bob similar to the way Alice and Bob exchange the key. How do we figure out that the other end is trust-worthy enough to exchange communications? The solution is authentication with certificates and PKI (Public Key Infrastructure). The process would require the user to have valid certificate that is trusted by the `root`. Before the DHKE process, the root send the user one of its asymmetric key in private! Afther the DHKE process, root's certificate containing the other asymmetric key information will be sent. Assume that we use RSA, if the trusted user knows the key `d` (which is exchanged in private), the key `e` and `n` (which are the public keys) are digitally signed using RSA (or another asymmetric algorithm) to ensure its authenticity from the root. This way, Eve can't also exchange communications with Alice or Bob since they can verify the root's certificate signature. The value of the RSA's keys must also be big enough so that they are not breakable.

Let's continue the process:
```
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
        r.sendline(base64.b64encode(cipher_encrypt.encrypt(pad(inp, cipher_encrypt.block_size)))

    user_certificate_data = {
        "name":name.decode(), # convert bytestring into string
        "key": {
            "e":65537,
            "n":12345
        },
        "signer":"root"
    }
    decoy(user_certificate_data)
    user_certificate_signature = b"test"
    decoy(user_certificate_signature)
    user_signature = b"test"
    decoy(user_signature)
```

Here, I create the sending function `decoy` according to the function `decrypt_input_b64` from the server. I also choose random variables depends on what I have. In this case, I only know that my signer is "root" since I received the `root`'s key, which is key `d`. Let's run the program (don't forget to put `exit()` to avoid unnecessary error logs):
```
 python3 solution.py
[+] Starting local process '/challenge/run': pid 169
/home/hacker/solution.py:152: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline(hex(B))
[*] Stopped process '/challenge/run' (pid 169)
hacker@cryptography~tls-2:~$
```
The program exits normally. Let's check what's the server sent us (I used `print(r.recvall())` in this case):
```
b'B: user certificate (b64): user certificate signature (b64): user signature (b64): Invalid user certificate key n value (2**512 < n < 2**1024)\n'
```

So, we haven't met the requirements. We have to generate different RSA keys. By using `getPrime(512)` (which generates a random prime value that's around 512 bits), we generate both `p` and `q` to contruct our own key (part of my `main` function):
```
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
    user_key_d = inverse(user_key_e, phi) # The same as using pow(user_key_e, -1, phi)
    user_certificate_data = {
        "name":name.decode(), # convert bytestring into string
        "key": {
            "e":user_key_e,
            "n":n
        },
        "signer":"root"
    }
    decoy(json.dumps(user_certificate_data).encode())
    user_certificate_signature = b"test"
    decoy(user_certificate_signature)
    user_signature = b"test"
    decoy(user_signature)
    print(r.recvall())
    exit()
```

This time, we received different output:
```
b'B: user certificate (b64): user certificate signature (b64): user signature (b64): Untrusted user certificate: invalid signature\n'
```

Let's find out the way the construct according to this section of code:
```
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
```

Our `user_signer` is "root". Consequently, `user_signer_key` will contains the `root`'s key and these keys will be used to decrypted the `user_certificate_signature`. We would have to encrypt our "signature" (which is our hash digest of the `user_certificate_data`) with the root's key `d`:
```
    user_certificate_signature = SHA256Hash(json.dumps(user_certificate_data).encode()).digest()
    user_certificate_signature = pow(
        int.from_bytes(user_certificate_signature, "little"),
        root_key_d,
        root_certificate_data["key"]["n"]
    ).to_bytes(256, "little")
    decoy(user_certificate_signature)
```

And, I got a new output:
```
b'B: user certificate (b64): user certificate signature (b64): user signature (b64): Untrusted user: invalid signature\n'
```

Let's check the end section of the code:
```
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
```

Similar to what we did above, we would have to encrypt, again, our "DHK signature" but with our RSA keys. This "DHK signature" is not a hash digest of `s` but a hash digest of both `A` and `B` instead.  
Why wouldn't we wanna use hash digest of `s`? Because we don't wanna reveal `s`, which should be in private. Instead, `A` and `B` are both public and can be used to sign. This protocol ensures that both parties agree on the asymmetric public keys they are using. The attacker won't be able to sign on our behalf without the value `s` and our RSA asymmetric key. Only our intended recipient (which is the root) can decrypt and verify the signature. You can adjust the `user_signature` as below:
```
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
    print(r.recvall())
    exit()
```

And, I got a different output:
```
b'B: user certificate (b64): user certificate signature (b64): user signature (b64): secret ciphertext (b64): 8yRkMxRr9Uwlm+J5mDxTnu0L3X9NiuWObBLl2WLHsBgW9Al2YksFkIPaSAWYCzr0pN7LAviyUDE5xqbwUaS4mA==\n'
```

Let's decrypt this with `cipher_decrypt`:
```
    r.recvuntil(b"secret ciphertext (b64): ")
    cipher_text = r.recvline()[:-1]
    print(unpad(cipher_decrypt.decrypt(base64.b64decode(cipher_text)), cipher_decrypt.block_size))
    exit()
```

And I got the output I wanted:
```
b'pwn.college{8-aCC_rKxTelwoMlnbQJlxe6BUW.dZDOzMDL5kTN5YzW}\n'
```

One thing to notice: if the key value `s` get leaked, it can compromise the current communications. However, it won't affect the past communications. Luckily, the key value `s` is unique to each session. This only impacts the future communication where the same `s` is used.  
HTTP Secure (HTTPS) is a modification of the HTTP protocol designed to utilize Transport Layer Security (TLS) or Secure Sockets Layer (SSL) with older applications for data security.  
Before the TLS mechanism was in place, we were vulnerable to Man-in-the-middle attacks and other types of reconnaissance or hijacking, meaning anyone in the same LAN as the client or server could view the web traffic if they were listening on the wire. We can now have security implemented in the browser enabling everyone to encrypt their web habits, search requests, sessions or data transfers, bank transactions, and much more.  
TLS Handshake Via HTTPS:
![image](https://github.com/user-attachments/assets/4e6033c4-5816-4b82-a96f-7b35f1c7c5ca)

In the first few packets, we can see that the client establishes a session to the server using port 443 boxed in blue. This signals the server that it wishes to use HTTPS as the application communication protocol.

Once a session is initiated via TCP, a TLS ClientHello is sent next to begin the TLS handshake. During the handshake, several parameters are agreed upon, including session identifier, peer x509 certificate, compression algorithm to be used, the cipher spec encryption algorithm, if the session is resumable, and a 48-byte master secret shared between the client and server to validate the session.

Once the session is established, all data and methods will be sent through the TLS connection and appear as TLS Application Data as seen in the red box. TLS is still using TCP as its transport protocol, so we will still see acknowledgment packets from the stream coming over port 443.

To summarize the handshake:

- Client and server exchange hello messages to agree on connection parameters.
- Client and server exchange necessary cryptographic parameters to establish a premaster secret.
- Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
- Generate a master secret from the premaster secret and exchanged random values.
- Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
- Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.

Before the TLS handshake: You, as the server, need to request and receive a certificate from the CA by submitting a CSR. Digital certificates (signed by a trusted CA) that conform to X.509 contain the following data:
1. Version of X.509 to which the certificate conforms.
2. Serial number (from the certificate creator)
3. Signature algorithm identifier (specifies the technique used by the certificate authority to digitally sign the contents of the certificate)
4. Issuer name (identification of the certificate authority that issued the certificate)
5. Validity period (specifies the dates and times-a starting data and time and an expiration data and time-during which the certificate is valid)
6. Subject’s name (contains the common name [CN] of the certificate as well as the distinguished name [DN] of the entity that owns the public key contained in the certificate)
7. Subject’s public key (the meat of the certificate-the actual public key the certificate owner used to set up secure communications).  

Certificates may be issued for a variety of purposes. These include providing assurance for the public keys of  
- Computers/machines
- Individual users
- Email addresses
- Developers (code-signing certificates)

Some major CAs: Symantec, IdenTrust, AWS, GlobalSign, Comodo, Certum, GoDaddy, DigiCert, Secom, Entrust, Actalis, Trustwave.  
If you configure your browser to trust a CA, it will automatically trust all of the digital certificates issued by that CA. Browser developers pre-configure browsers to trust the major CAs to avoid placing this burden on users. “Let’s Encrypt!” is a well-known CA because they offer free certficates in an effort to encourage the use of encryption.  
Registration authorities (RAs) assist CAs with the burden of verifying users’ identities prior to issuing digital certificates.  
CA must carefully protect their own private keys to preserve their trust relationships. They often use an **offline** CA to protect their **root certificate**, the top-level certificate for their entire PKI.
