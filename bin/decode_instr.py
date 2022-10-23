#!/usr/bin/env python3

from pathlib import Path
import sys
sys.path.append(str((Path(__file__).parent / '..').resolve()))

import encoding

if True:
    inst_bytes = bytes.fromhex(sys.argv[1])[::-1]
    print(f"inst_bytes: {inst_bytes.hex()}")

    enc = encoding.Encodings().find_inst(inst_bytes, False)
    print(enc)

if False:
    encs = encoding.Encodings()
    print(encs.encs)
