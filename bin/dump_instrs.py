#!/usr/bin/env python3

from pathlib import Path
import sys
sys.path.append(str((Path(__file__).parent / '..').resolve()))

import encoding

encs = encoding.Encodings()

for enc in encs.encs:
    bm = enc.bitmask()
    bp = enc.bitpattern()
    bms = f"{bm:#034b}"[2:]
    bs = list(f"{bp:#034b}"[2:])
    for i in range(len(bs)):
        if bms[i] == "0":
            bs[i] = "-"
    bs = "".join(bs)
    print(f"{bs};{enc.mnemonic};{enc.name};{bm:#010x}")
