#!/usr/bin/env python3

"""
Unpack ARM instruction XML files extracting the encoding information.
Pickle it.
"""

import argparse
from pathlib import Path
import pickle
import sys

sys.path.append(str((Path(__file__).parent / "..").resolve()))

import encoding
from instrs2asl import *
from rich import print

instr_dill_path = (Path(__file__).parent / "../encoding/instr_encodings.pickle").resolve()


def real_main(args):
    print(f"Writing pickled encodings to '{args.output}'")

    decoder_files = [ 'encodingindex.xml' ]
    decoders = [ readDecodeFile(d, f) for df in decoder_files for d in args.dir for f in glob.glob(os.path.join(d, df)) ]
    a64_decoder = decoders[0]
    groups, classes = a64_decoder
    print(a64_decoder)
    # print("\n".join(map(str, groups)))
    # print("\n".join(map(str, classes)))
    with open(args.output, "wb") as outfile:
        pickle.dump(object(), outfile, protocol=2)


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", "-v", help="Use verbose output", action="count", default=0)
    parser.add_argument(
        "dir",
        metavar="<dir>",
        nargs="*",
        default=["v8.6/ISA_A64_xml_v86A-2019-12_OPT"],
        help="input directories",
    )
    parser.add_argument(
        "--arch",
        help="List of architecture states to extract",
        choices=["AArch32", "AArch64"],
        action="append",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="File to store pickled encodings",
        metavar="FILE",
        default=instr_dill_path,
    )
    return parser


def main():
    real_main(get_arg_parser().parse_args())


if __name__ == "__main__":
    main()
