#!/usr/bin/python3

from pathlib import Path
import os
import sys

if len(sys.argv) > 1:
    f = Path(sys.argv[1])
    fs = f.with_stem(f.stem + '-stripped')
    print(fs)
    fb = bytearray(f.read_bytes())
    ind = 0
    l = len(fb)
    while ind < l:
        fb[ind] &= 0x7f
        ind += 1
    fs.write_bytes(fb)

