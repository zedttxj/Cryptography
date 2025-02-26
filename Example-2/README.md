**INCOMPLETE-WILL BE FINISHED IN A DAY**

# TLS 2 [pwn.college](https://pwn.college/cse365-f2024/cryptography/)

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

### 3. Continue the process
