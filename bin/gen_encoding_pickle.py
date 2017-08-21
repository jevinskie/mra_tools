#!/usr/bin/env python3

'''
Unpack ARM instruction XML files extracting the encoding information.
Pickle it.
'''
from __future__ import print_function

from builtins import str
from builtins import object
import argparse
import glob
import itertools
import os
import pickle
import re
import sys
import xml.etree.cElementTree as ET

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import encoding

instr_dill_path = os.path.join(os.path.dirname(__file__), '../encoding/instr_encodings.pickle')

########################################################################
# Lazy Coding Globals
########################################################################

g_instrs = None
g_instrs_encs = None
g_instrs_enc_objs = None


########################################################################
# Utility Functions
########################################################################

def list2tuple(a):
    return tuple((list2tuple(x) if isinstance(x, list) or isinstance(x, tuple) else x for x in a))


########################################################################
# Classes
########################################################################

class Instruction(object):
    '''Representation of Instructions'''

    def __init__(self, name, encs):
        self.name = name
        self.encs = list2tuple(encs)
        self.enc_objs = []
        for enc in encs:
            name = enc[0]
            encoding_str = enc[1]
            fields = tuple(enc[2])
            ne_fields = tuple(enc[3])
            form = enc[4]
            self.enc_objs.append(encoding.Encoding(name, encoding_str, fields, ne_fields, form))
        self.enc_objs = tuple(self.enc_objs)

    def __repr__(self):
        encs = '[' + ', '.join([inm for (inm, _, _, _, _) in self.encs]) + ']'
        return 'Instruction{' + ', '.join([str(self.enc_objs), self.name]) + '}'


########################################################################
# Extracting information from XML files
########################################################################

'''
Read pseudocode to extract an ASL name.
'''


def readASLName(ps):
    name = ps.attrib['name']
    name = name.replace('.txt', '')
    name = name.replace('/instrs', '')
    name = name.replace('/Op_', '/')

    return name


def readInstruction(xml):
    execs = xml.findall(".//pstext[@section='Execute']/..")
    assert (len(execs) <= 1)
    if not execs: return None  # discard aliases

    exec_name = readASLName(execs[0])

    # for each encoding, read instructions encoding, matching decode ASL and index
    encs = []
    for iclass in xml.findall('.//classes/iclass'):
        encoding = iclass.find('regdiagram')
        form = encoding.attrib['form']
        isT16 = form == '16'
        insn_set = 'T16' if isT16 else iclass.attrib['isa']

        ne_fields = []

        fields = []
        for b in encoding.findall('box'):
            wd = int(b.attrib.get('width', '1'))
            hi = int(b.attrib['hibit'])
            # normalise T16 encoding bit numbers
            if isT16: hi = hi - 16
            lo = hi - wd + 1
            nm = b.attrib.get('name', '_')
            ignore = 'psbits' in b.attrib and b.attrib['psbits'] == 'x' * wd
            consts = ''.join(['x' * int(c.attrib.get('colspan', '1')) if c.text is None or ignore else c.text for c in
                              b.findall('c')])

            # if adjacent entries are two parts of same field, join them
            # e.g., imm8<7:1> and imm8<0> or opcode[5:2] and opcode[1:0]
            m = re.match('^(\w+)[<[]', nm)
            if m:
                nm = m.group(1)
                split = True
                if fields[-1][3] and fields[-1][2] == nm:
                    (hi1, lo1, _, _, c1) = fields.pop()
                    assert (lo1 == hi + 1)  # must be adjacent
                    hi = hi1
                    consts = c1 + consts
            else:
                split = False

            if consts.startswith('!= '):
                ne_fields.append((hi, lo, nm, split, consts[3:]))

            # discard != information because it is better obtained elsewhere in spec
            if consts.startswith('!= '): consts = 'x' * wd

            fields.append((hi, lo, nm, split, consts))

        # workaround: avoid use of overloaded field names
        fields2 = []
        for (hi, lo, nm, split, consts) in fields:
            if (nm in ['SP', 'mask', 'opcode']
                and 'x' not in consts
                and exec_name not in ['aarch64/float/convert/fix', 'aarch64/float/convert/int']):
                # workaround: avoid use of overloaded field name
                nm = '_'
            fields2.append((hi, lo, nm, split, consts))

        dec_asl_name = readASLName(iclass.find('ps_section/ps'))

        name = dec_asl_name if insn_set in ['T16', 'T32', 'A32'] else encoding.attrib['psname']
        encs.append((name, insn_set, fields2, ne_fields, form))

    return Instruction(exec_name, encs)


def getInstrs(dirs, arches, verbose_level):
    encodings = []
    print('Arches: ', arches)
    if 'AArch32' in arches: encodings.extend(['T16', 'T32', 'A32'])
    if 'AArch64' in arches: encodings.extend(['A64'])
    if verbose_level > 0:
        if encodings != []:
            print('Selecting encodings', ', '.join(encodings))
        else:
            print('Selecting entire architecture')

    instrs = []
    for d in dirs:
        for inf in glob.glob(os.path.join(d, '*.xml')):
            name = re.search('.*/(\S+).xml', inf).group(1)
            if name == 'onebigfile': continue
            xml = ET.parse(inf)
            instr = readInstruction(xml)
            if instr is None: continue

            if encodings != []:  # discard encodings from unwanted InsnSets
                encs = tuple([e for e in instr.encs if e[1] in encodings])
                if encs == []:
                    if verbose_level > 1: print('Discarding', instr.name, encodings)
                    continue
                instr.encs = encs

            instrs.append(instr)

    return tuple(instrs)


########################################################################
# Main
########################################################################

def main():
    global g_instrs
    global g_instrs_encs
    global g_instrs_enc_objs

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', help='Use verbose output',
                        action='count', default=0)
    parser.add_argument('dir', metavar='<dir>', nargs='*',
                        default=['v8.3/ISA_v83A_AArch32_xml_00bet4'], help='input directories')
    parser.add_argument('--arch', help='Optional list of architecture states to extract',
                        choices=['AArch32', 'AArch64'], default=['AArch32'], action='append')
    parser.add_argument('--output',  '-o', help='File to store pickled encodings',
                        metavar='FILE', default=instr_dill_path)
    args = parser.parse_args()

    g_instrs = getInstrs(args.dir, args.arch, args.verbose)
    g_instrs_encs = tuple(itertools.chain(*(i.encs for i in g_instrs)))
    g_instrs_enc_objs = tuple(itertools.chain(*(i.enc_objs for i in g_instrs)))

    print('Writing pickled encodings to \'%s\'' % args.output)
    with open(args.output, 'wb') as outfile:
        pickle.dump(g_instrs_enc_objs, outfile, protocol=2)

    return


if __name__ == '__main__':
    sys.exit(main())
