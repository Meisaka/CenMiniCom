#!/usr/bin/python3

from pathlib import Path
import os
import sys
import argparse

parser = argparse.ArgumentParser(description='scan Centurion archive format disk images',add_help=True)
parser.add_argument('file')
parser.add_argument('seek_track', help='start scaning from track, in hex', default='10', nargs='?')
inargs = parser.parse_args()

f = Path(inargs.file)
start = int(inargs.seek_track, 16)
fb = bytearray(f.read_bytes())
ind = 0
l = len(fb)
def clearhi(v):
    i = 0
    while i < len(v):
        v[i] &= 0x7f
        i += 1

while ind < 100:
    sec = start * 0x200
    name1 = fb[sec:sec+0x0a]
    ent1 = fb[sec+0x0a:sec+0x12]
    name2 = fb[sec+0x12:sec+0x1c]
    ent2_seq = fb[sec+0x1c:sec+0x1d]
    ent2_xseq = fb[sec+0x1d:sec+0x1f]
    ent2_ftype = fb[sec+0x1f:sec+0x20]
    ent2_xtype = fb[sec+0x20:sec+0x22]
    sec_len = fb[sec+0x22:sec+0x25]
    ent2_o1c = fb[sec+0x25:sec+0x2c]
    sec_next = fb[sec+0x2c:sec+0x2f]
    ent2_nil = fb[sec+0x2f:sec+0x30]
    name3 = fb[sec+0x30:sec+0x3a]
    ent3 = fb[sec+0x3a:sec+0x40]
    clearhi(name1)
    clearhi(name2)
    clearhi(name3)
    sec_fmt = [
        ent2_seq.hex(),
        ent2_xseq.hex(),
        ent2_ftype.hex(),
        ent2_xtype.hex(),
        sec_len.hex(),
        ent2_o1c.hex(),
        sec_next.hex(),
        ent2_nil.hex()
    ]
    print(start.to_bytes(2,'big').hex(),':',sec.to_bytes(4,'big').hex(),' -> ',
            ent1.hex(),'-',':'.join(sec_fmt),'-',ent3.hex(),' - ',
        repr(str(name3.rstrip(),'ascii')),',',
        repr(str(name1.rstrip(),'ascii')),',',
        repr(str(name2.rstrip(),'ascii')),
        sep='')
    start = int.from_bytes(sec_next, 'big')
    if start >= 0xffffff or start == 0:
        break
    ind += 1

