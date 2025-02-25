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

def ciph(inp, desired_output):
    for c in range(16):
        print(c)
        for i in range(256): # changing the last character of the IV block 256 times
            inp = inp[:(15-c)] + bytes([i]) + inp[(16-c):]
            if decoy(inp,5) == b"Unknown command!\n":
                print(f"Correct padding: {i}")
                inp = inp[:(15-c)] + bytes([inp[i+15-c]^(c+1)^(c+2) for i in range(c+1)]) + inp[16:]
                break
    return bytes([inp[i]^0x17^desired_output[i] for i in range(16)]) + inp[16:] # converting to desired output

org = b"please give me the flag, kind worker process!"
org = org + bytes([(len(org)+15)%16+1]*((len(org)+15)%16+1)) # padding
print(org)
result = b"A"*16
for i in range(len(org)//16):
    result = ciph(b"A"*16+result,org[-16:])
    org = org[:-16]

# The program will automatically print the flag without having to call `decoy` again
