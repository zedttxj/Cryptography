import subprocess
import random
import struct
import os


data = b""
with open("/challenge/flag.cimg","rb") as inp:
    data = inp.read()
jmp = 0
ind = 12
flag = b""
ch = []
#print(int.from_bytes(data[8:12],"little"))
for i in range(int.from_bytes(data[8:12], "little")):
    if data[ind] == 3:
        print(data[ind+3],data[ind+4])
        #ind += data[ind+3]*data[ind+4]+5
        ind += 5
        tmp = b""
        for j in range(8):
            for k in range(7):
                tmp += bytes([data[ind]])
                ind += 1
            tmp += b"\n"
        ch.append(tmp)
    elif data[ind] == 4:
        flag += bytes([data[ind+2]])
        ind += 8
    else: print("error")
str = b""
ls = []
txt = []
for i in range(256):
    txt.append(subprocess.check_output(["/usr/bin/figlet","-fascii9"], input=bytes([i])))
for i in flag:
    if not i in ls: ls.append(i)
    str += bytes([txt.index(ch[ls.index(i)])])
pritn(str)
