# AES-CBC-POA-Encrypt [pwn.college](https://pwn.college/cse365-f2024/cryptography/)
## Challenge Overview

You're not going to believe this, but... a Padding Oracle Attack doesn't just let you decrypt arbitrary messages: it lets you encrypt arbitrary data as well! This sounds too wild to be true, but it is. Think about it: you demonstrated the ability to modify bytes in a block by messing with the previous block's ciphertext. Unfortunately, this will make the previous block decrypt to garbage. But is that so bad? You can use a padding oracle attack to recover the exact values of this garbage, and mess with the block before that to fix this garbage plaintext to be valid data! Keep going, and you can craft fully controlled, arbitrarily long messages, all without knowing the key! When you get to the IV, just treat it as a ciphertext block (e.g., plop a fake IV in front of it and decrypt it as usual) and keep going! Incredible.

Now, you have the knowledge you need to get the flag for this challenge. Go forth and forge your message!

FUN FACT: Though the Padding Oracle Attack was discovered in 2002, it wasn't until 2010 that researchers figured out this arbitrary encryption ability. Imagine how vulnerable the web was for those 8 years! Unfortunately, padding oracle attacks are still a problem. Padding Oracle vulnerabilities come up every few months in web infrastructure, with the latest (as of time of writing) just a few weeks ago!

# My Approach

Recall that PKCS7 padding adds N bytes with the value N, so if 11 bytes of padding were added, they have the value 0x0b. During unpadding, PKCS7 will read the value N of the last byte, make sure that the last N bytes (including that last byte) have that same value, and remove those bytes. If the value N is bigger than the block size, or the bytes don't all have the value N, most implementations of PKCS7, including the one provided by PyCryptoDome, will error.

Consider how careful you had to be in the previous level with the padding, and how this required you to know the letter you wanted to remove. What if you didn't know that letter? Your random guesses at what to XOR it with would cause an error 255 times out of 256 (as long as you handled the rest of the padding properly, of course), and the one time it did not, by known what the final padding had to be and what your XOR value was, you can recover the letter value! This is called a Padding Oracle Attack, after the "oracle" (error) that tells you if your padding was correct!

By analyzing `worker.py`, we can tell when the program will results in error if our encrypted message doesn't have the correct padding. If we have correct paddding, the program will return the value `Unknown command!`. Our goal is to generate the encrypted message that matches the value `please give me the flag, kind worker process!`. To do that, we have to understand about padding and CBC.

## What is padding?

One padding standard (and likely the most popular) is PKCS7, which simply pads the input with bytes all containing a value equal to the number of bytes padded. If one byte is added to a 15-byte input, it contains the value 0x01, two bytes added to a 14-byte input would be 0x02 0x02, and the 15 bytes added to a 1-byte input would all have a value 0x0f. During unpadding, PKCS7 looks at the value of the last byte of the block and removes that many bytes. Simple!

But wait... What if exactly 16 bytes of plaintext are encrypted (e.g., no padding needed), but the plaintext byte has a value of 0x01? Left to its own devices, PKCS7 would chop off that byte during unpadding, leaving us with a corrupted plaintext. The solution to this is slightly silly: if the last block of the plaintext is exactly 16 bytes, we add a block of all padding (e.g., 16 padding bytes, each with a value of 0x10). PKCS7 removes the whole block during unpadding, and the sanctity of the plaintext is preserved at the expense of a bit more data.

## How does Cipher Block Chaining (CBC) work?

Each ciphertext block has 16 characters. CBC mode encrypts blocks sequentially, and before encrypting plaintext block number N, it XORs it with the previous ciphertext block (number N-1). When decrypting, after decrypting ciphertext block N, it XORs the decrypted (but still XORed) result with the previous ciphertext block (number N-1) to recover the original plaintext block N. For the very first block, since there is no "previous" block to use, CBC cryptosystems generate a random initial block called an Initialization Vector (IV). The IV is used to XOR the first block of plaintext, and is transmitted along with the message (often prepended to it). This means that if you encrypt one block of plaintext in CBC mode, you might get two blocks of "ciphertext": the IV, and your single block of actual ciphertext.

How do we manipulate this? Consider crafting a cipher text for 15 characters. It means that we would have to have one IV block and one cipher block. When the cipher text is decrypted, we should have the message with the last character as `0x1` (since there's only 1 character padded). In this case, which block you would adjust (the 1st block or the 2nd block) characters by characters without messing the whole content of the block? Should we consider changing the original content of the 1st block or the 2nd block?  

The second question is easier to answer: we should change the orginal content of the 2nd block since the original content of the 1st (which is IV block) will be discarded. Of course, changing either the 1st block or the 2nd block would change the original content of both blocks. That begs the question: which block should we change (in the encrypted form) to adjust the decrypted content of the 2nd block?  

We don't need to pay attention to the 1st block for now. Consider changing 1 character at a time in the encrypted format. If we change 1 character in the 2nd block, all 16 characters of the 2nd block's original content would change. That would take 2**8 times to get 50% chances (birthday attack priciple) of figuring out the correct block that has correct content we want. However, if we change 1 character in the 1st block in the encrypted format, only 1 character change in the orignial content of the 2nd block. Technically speaking, we would need 256*16 tries to figure out the correct content.

The `worker.py` can tell us when our cipher text has correct padding or not. For the cipher text to have the correct padding with just 1 character adjustment, consider changing the last character of the 1st block and we will be able to have the original block with `0x1` as the last character. Let's say we change the 1st character of the 1st block instead. In this case, we would have to change the whole block for the computer to have correct padding, where all 16 characters have to contain value `0x16`.

Assume that when we change the last character of the first block into 'A' (`0x41`), we got the message `Unknown command!`. In this case, the decrypted message has the padding of `0x1`. In the next last character, we would have to change the last character in the encrypted form in a way that its original decrypted message would have the padding `0x2` in its last character. By performing XOR operation, we have `0x41^0x1^0x2`=`0x42` as the value of the last character.

*We assume that you know how XOR operation works. If you don't, don't worry! Like addition, subtraction, and multiplication, XOR is an operator that can be used in the integer field. There's more to it. If you perform XOR operation twice with the same value, it returns to the original value. For example, `0x49`^`0x2`^`0x2` (where "^" is the XOR operator) returns to `0x49`. `0x49`^`0x2`^`0x2`^`0x2`^`0x2` is also equal to `0x49`.*

With that said, let's dive in!

### 1. Changing the last character of the 1st block in encrypted format

Let's run this code:
```
from pwn import *
import base64

r = ssh('hacker', 'pwn.college', keyfile="./key")
p = r.run(b"/bin/bash")

def decoy(inp, rea):
        inp = base64.b64encode(inp)
        p.sendline("/challenge/worker")
        p.sendline(b"TASK: " + inp)
        out = p.recvline()[-17:]
        if out != b"Unknown command!\n":
            for i in range(rea):
                #print(i, p.recvline())
                p.recvline()
        return out

print(decoy(b"A"*32,9)) # this step is for cleaning the output
inp = b"A"*32 # Our input
for i in range(256): # changing the last character of the IV block 256 times
    inp = inp[:15] + bytes([i]) + inp[16:]
    print(i, decoy(inp,5))
```

You may adjust the 2nd parameter of the `decoy` function depends on how its output match what you would expect. Here, I changed it into `9` for the cleaning step and then `5` when I loop through 256 possible characters. After that, I ran the program:

```
242 b'cent call last):\n'
243 b'cent call last):\n'
244 b'cent call last):\n'
245 b'cent call last):\n'
246 b'cent call last):\n'
247 b'cent call last):\n'
248 b'cent call last):\n'
249 b'Unknown command!\n'
250 b'cent call last):\n'
251 b'cent call last):\n'
252 b'cent call last):\n'
253 b'cent call last):\n'
254 b'cent call last):\n'
255 b'cent call last):\n'
[*] Closed SSH channel with pwn.college
```

Notice that character with the value `249` (`0xf9`) gives the correct padding, which will make the value of the last character of the 2nd block `0x1` in original message. In other word, if our input is `b"A"*32` (32 characters A), or original message would be `b"A"*16+b"?"*15+bytes([0x1])` in this case (assume that "?" is an unknown character).

### 2. Changing the 2nd character of the first block in encrypted format

Let's try figuring the correct padding for the second character. We would have to change the last character into `0xf9^0x1^0x2` as well. Before that, let's check how the terminal handle out if it receives correct padding. In my case, the correct padding input is `b"AAAAAAAAAAAAAAAxAAAAAAAAAAAAAAAA"`. Let's convert this into base64:
```
$ python3
Python 3.10.12 (main, Jan 17 2025, 14:35:34) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> print(base64.b64encode(b"AAAAAAAAAAAAAAAxAAAAAAAAAAAAAAAA"))
b'QUFBQUFBQUFBQUFBQUFBeEFBQUFBQUFBQUFBQUFBQUE='
>>>
$ ssh hacker@pwn.college
Connected!
hacker@cryptography~aes-cbc-poa-encrypt:~$ /challenge/worker
TASK: QUFBQUFBQUFBQUFBQUFBeEFBQUFBQUFBQUFBQUFBQUE=
Unknown command!
TASK: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
Traceback (most recent call last):
  File "/challenge/worker", line 20, in <module>
    plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
  File "/usr/local/lib/python3.8/dist-packages/Crypto/Util/Padding.py", line 92, in unpad
    raise ValueError("Padding is incorrect.")
ValueError: Padding is incorrect.
hacker@cryptography~aes-cbc-poa-encrypt:~$
```

I put 2 different inputs: the first one has the correct padding and the second one has incorrect padding. It seems our output still produces the same number of lines. So that's one extra line of output. I wrote the code to check if we can find the correct value for the next last character:
```
from pwn import *
import base64

r = ssh('hacker', 'pwn.college', keyfile="./key")
p = r.run(b"/bin/bash")

def decoy(inp, rea):
        inp = base64.b64encode(inp)
        p.sendline("/challenge/worker")
        p.sendline(b"TASK: " + inp)
        out = p.recvline()[-17:]
        if out != b"Unknown command!\n":
            for i in range(rea):
                #print(i, p.recvline())
                p.recvline()
        else:
            p.sendline(b"TASK: QUFBQUFBQUFBQUFBQUFBQQ==") # send incorrect padding to close the program
            for i in range(rea+1):
                p.recvline()
        return out

decoy(b"A"*32,9) # this step is for cleaning the output
inp = b"A"*32 # Our input
for i in range(256): # changing the last character of the IV block 256 times
    inp = inp[:15] + bytes([i]) + inp[16:]
    if decoy(inp,5) == b"Unknown command!\n":
        print(f"Correct padding: {i}")
        break

inp = inp[:15] + bytes([inp[15]^0x1^0x2]) + inp[16:]

for i in range(256):
    inp = inp[:14] + bytes([i]) + inp[15:]
    if decoy(inp,5) == b"Unknown command!\n":
        print(f"Correct padding: {i}")
        break
```

Then, I ran it:
```
Correct padding: 120
Correct padding: 242
[*] Closed SSH channel with pwn.college
```

Perfect! In the next step, we will run through each character and complete the whole block of 16 characters. You can write something like this or better:
```
from pwn import *
import base64

r = ssh('hacker', 'pwn.college', keyfile="./key")
p = r.run(b"/bin/bash")

def decoy(inp, rea):
        inp = base64.b64encode(inp)
        p.sendline("/challenge/worker")
        p.sendline(b"TASK: " + inp)
        out = p.recvline()[-17:]
        if out != b"Unknown command!\n":
            for i in range(rea):
                #print(i, p.recvline())
                p.recvline()
        else:
            p.sendline(b"TASK: QUFBQUFBQUFBQUFBQUFBQQ==") # send incorrect padding to close the program
            for i in range(rea+1):
                p.recvline()
        return out

decoy(b"A"*32,9) # this step is for cleaning the output
inp = b"A"*32 # Our input
for c in range(16):
    print(c) # Check if we missing any characters
    for i in range(256): # changing the last character of the IV block 256 times
        inp = inp[:(15-c)] + bytes([i]) + inp[(16-c):]
        if decoy(inp,5) == b"Unknown command!\n":
            print(f"Correct padding: {i}")
            inp = inp[:(15-c)] + bytes([inp[i+15-c]^(c+1)^(c+2) for i in range(c+1)]) + inp[16:]
            break
```

And, it worked:

```
0
Correct padding: 120
1
Correct padding: 242
2
Correct padding: 100
3
Correct padding: 87
4
Correct padding: 42
5
Correct padding: 225
6
Correct padding: 165
7
Correct padding: 255
8
Correct padding: 188
9
Correct padding: 181
10
Correct padding: 88
11
Correct padding: 69
12
Correct padding: 146
13
Correct padding: 217
14
Correct padding: 199
15
Correct padding: 71
[*] Closed SSH channel with pwn.college
```

Additionally, we put into a function that changes 2 blocks of text (which includes 32 characters) according to how we want our original message be with 2 parameters input and desired output.

### 3. Finalize the idea

I mentioned above that we can put everything into a function to return the encrypted format of the desired output we want. Notice that to change the original message of the 2nd block, we just change the first block in encrypted format. Consequently, we have to start the process from the right most block to the left most block and everytime we run that function, we just have to add extra 16 random characters at the head of the `inp` and it still works:
```

```
