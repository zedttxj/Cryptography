# AES-CBC-POA-Encrypt
**[pwn.college CSE365 Cryptography Course](https://pwn.college/cse365-f2024/cryptography/)**
## Challenge Overview

You're not going to believe this, but... a Padding Oracle Attack doesn't just let you decrypt arbitrary messages: it lets you encrypt arbitrary data as well! This sounds too wild to be true, but it is. Think about it: you demonstrated the ability to modify bytes in a block by messing with the previous block's ciphertext. Unfortunately, this will make the previous block decrypt to garbage. But is that so bad? You can use a padding oracle attack to recover the exact values of this garbage, and mess with the block before that to fix this garbage plaintext to be valid data! Keep going, and you can craft fully controlled, arbitrarily long messages, all without knowing the key! When you get to the IV, just treat it as a ciphertext block (e.g., plop a fake IV in front of it and decrypt it as usual) and keep going! Incredible.

Now, you have the knowledge you need to get the flag for this challenge. Go forth and forge your message!

FUN FACT: Though the Padding Oracle Attack was discovered in 2002, it wasn't until 2010 that researchers figured out this arbitrary encryption ability. Imagine how vulnerable the web was for those 8 years! Unfortunately, padding oracle attacks are still a problem. Padding Oracle vulnerabilities come up every few months in web infrastructure, with the latest (as of time of writing) just a few weeks ago!

# My Approach

Recall that PKCS7 padding adds N bytes with the value N, so if 11 bytes of padding were added, they have the value 0x0b. During unpadding, PKCS7 will read the value N of the last byte, make sure that the last N bytes (including that last byte) have that same value, and remove those bytes. If the value N is bigger than the block size, or the bytes don't all have the value N, most implementations of PKCS7, including the one provided by PyCryptoDome, will error.

Consider how careful you had to be in the previous level with the padding, and how this required you to know the letter you wanted to remove. What if you didn't know that letter? Your random guesses at what to XOR it with would cause an error 255 times out of 256 (as long as you handled the rest of the padding properly, of course), and the one time it did not, by known what the final padding had to be and what your XOR value was, you can recover the letter value! This is called a Padding Oracle Attack, after the "oracle" (error) that tells you if your padding was correct!
