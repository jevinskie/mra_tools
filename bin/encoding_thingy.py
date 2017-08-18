#!/usr/bin/env python3

'''
Unpack ARM instruction XML files extracting the encoding information
and ASL code within it.
'''

import argparse, glob, itertools, os, re, struct, sys
import xml.etree.cElementTree as ET

########################################################################
# Lazy Coding Globals
########################################################################

instrs = None
instrs_encs = None
instrs_enc_objs = None

########################################################################
# Utility Functions
########################################################################

def list2tuple(a):
    return tuple((list2tuple(x) if isinstance(x, list) or isinstance(x, tuple) else x for x in a))

def tuple2list(a):
    return list((tuple2list(x) if isinstance(x, list) or isinstance(x, tuple) else x for x in a))

def is_thumb_inst_32_bit(inst):
    inst16 = None
    if isinstance(inst, bytes):
        inst16 = struct.unpack("<H", inst[:2])[0]
    elif isinstance(inst, int):
        if inst & 0xFFFF0000:
            inst16 = inst & 0xFFFF
        else:
            inst16 = inst
    else:
        raise ValueError("Bad type: %s" % (type(inst)))
    if inst16 & 0xf800 == 0xe000: # B T2
        return False
    elif inst16 & 0xe000 == 0xe000:
        return True
    else:
        return False

def get_inst_length(inst, thumb):
    if not thumb:
        return 4
    elif is_thumb_inst_32_bit(inst):
        return 4
    else:
        return 2

def swap_endian(n, length):
    if length == 4:
        return ((n & 0xFF000000) >> 24) <<  0 | \
               ((n & 0x00FF0000) >> 16) <<  8 | \
               ((n & 0x0000FF00) >>  8) << 16 | \
               ((n & 0x000000FF) >>  0) << 24
    elif length == 2:
        return ((n & 0xFF00) >> 8) << 0 | \
               ((n & 0x00FF) >> 0) << 8
    else:
        raise ValueError("Unhandled length: %d" % (length))

def swap_endian_32_halfwords(n):
    return ((n & 0xFF000000) >> 24) << 16 | \
           ((n & 0x00FF0000) >> 16) << 24 | \
           ((n & 0x0000FF00) >>  8) <<  0 | \
           ((n & 0x000000FF) >>  0) <<  8

def hex_str(n, length=None):
    if isinstance(n, int):
        assert(length != None)
        hex_strs = []
        for i in range(length):
            hex_strs.append("%02X" % (n & 0xFF))
            n >>= 8
        return " ".join(hex_strs)
    elif isinstance(n, bytes):
        return " ".join(["%02X" % (b) for b in n])
    else:
        raise ValueError("Bad type: %s" % (type(n)))

def find_inst(inst, thumb):
    global instrs_enc_objs

    if isinstance(inst, str):
        for enc in instrs_enc_objs:
            if enc.name != inst:
                continue
            return enc
        return None

    length = get_inst_length(inst, thumb)
    inst_int = None
    if isinstance(inst, bytes):
        if length == 4:
            inst_int = struct.unpack("<I", inst[:4])[0]
        elif length == 2:
            inst_int = struct.unpack("<H", inst[:2])[0]
        else:
            raise ValueError("Bad length %d" % length)
    elif isinstance(inst, int):
        inst_int = inst
    else:
        raise ValueError("Bad type")

    for enc in instrs_enc_objs:
        if enc.thumb != thumb:
            continue
        if enc.length != length:
            continue
        if enc != inst:
            continue
        return enc
    return None

########################################################################
# Classes
########################################################################

class Encoding:
    '''Representation of a particular Instruction Encoding'''

    def __init__(self, name, encoding_str, fields, ne_fields, form):
        self.name = name
        if encoding_str[0] == 'T' and encoding_str[0] != 'A':
            self.thumb = True
        elif encoding_str[0] == 'A' and encoding_str[0] != 'T':
            self.thumb = False
        else:
            raise ValueError("Can't decode ARM/Thumb from encoding '" + encoding_str + "'")
        if encoding_str[1:3] == "16":
            self.length = 2
        elif encoding_str[1:3] == "32" or encoding_str[1:3] == "64":
            self.length = 4
        else:
            raise ValueError("Bad encoding '" + encoding_str + "'")
        self.fields = fields
        self.ne_fields = ne_fields
        self.form = form

    def __eq__(self, other):
        inst_int = None
        if isinstance(other, bytes):
            if self.length == 4 and len(other) >= 4:
                inst_int = struct.unpack("<I", other[:4])[0]
            elif self.length == 2 and len(other) >= 2:
                inst_int = struct.unpack("<H", other[:2])[0]
            else:
                raise ValueError("Bad length %d vs %d" % (self.length, len(other)))
        elif isinstance(other, Encoding):
            return self.name == other.name
        elif isinstance(other, int):
            inst_int = other
        else:
            raise ValueError("Bad type: %s" % (type(other)))

        if self.thumb and self.length == 4:
            inst_int = swap_endian(inst_int, 4)

        if self.bitmask() & inst_int == self.bitpattern():
            if self.ne_bitmask() != 0 and self.ne_bitmask() & inst_int != self.ne_bitpattern():
                return True
            return True
        else:
            return False

    def bitmask(self):
        mask = 0
        for field in self.fields:
            (bit_hi, bit_lo, _, _, bitstr) = field
            for bit_num in range(bit_lo, bit_hi+1):
                str_idx = -bit_num + bit_lo - 1
                if bitstr[str_idx] == '1' or bitstr[str_idx] == '0':
                    mask |= 1 << bit_num
        if self.thumb and self.length == 4:
            mask = swap_endian_32_halfwords(mask)
        return mask

    def bitpattern(self):
        pattern = 0
        for field in self.fields:
            (bit_hi, bit_lo, _, _, bitstr) = field
            for bit_num in range(bit_lo, bit_hi+1):
                str_idx = -bit_num + bit_lo - 1
                if bitstr[str_idx] == '1':
                    pattern |= 1 << bit_num
        if self.thumb and self.length == 4:
            pattern = swap_endian_32_halfwords(pattern)
        return pattern

    def ne_bitmask(self):
        mask = 0
        for field in self.ne_fields:
            (bit_hi, bit_lo, _, _, bitstr) = field
            for bit_num in range(bit_lo, bit_hi+1):
                str_idx = -bit_num + bit_lo - 1
                if bitstr[str_idx] == '1' or bitstr[str_idx] == '0':
                    mask |= 1 << bit_num
        if self.thumb and self.length == 4:
            mask = swap_endian_32_halfwords(mask)
        return mask

    def ne_bitpattern(self):
        pattern = 0
        for field in self.ne_fields:
            (bit_hi, bit_lo, _, _, bitstr) = field
            for bit_num in range(bit_lo, bit_hi+1):
                str_idx = -bit_num + bit_lo - 1
                if bitstr[str_idx] == '1':
                    pattern |= 1 << bit_num
        if self.thumb and self.length == 4:
            pattern = swap_endian_32_halfwords(pattern)
        return pattern

    def __repr__(self):
        bitmask_hex_str = hex_str(swap_endian(self.bitmask(), self.length), length=self.length)
        bitpattern_hex_str = hex_str(swap_endian(self.bitpattern(), self.length), length=self.length)
        ne_bitmask_hex_str = hex_str(swap_endian(self.ne_bitmask(), self.length), length=self.length)
        ne_bitpattern_hex_str = hex_str(swap_endian(self.ne_bitpattern(), self.length), length=self.length)
        return "%s:\n\tbitmask:\t%s\n\tbitpattern:\t%s\n\tne_bitmask:\t%s\n\tne_bitpattern:\t%s\n\tthumb:\t%d\n\tlength:\t%d\n\tfields:\t%s\n\tne_fields:\t%s\n\tform:\t%s" % \
            (self.name, bitmask_hex_str, bitpattern_hex_str, ne_bitmask_hex_str, ne_bitpattern_hex_str, self.thumb, self.length, self.fields, self.ne_fields, self.form)


class Instruction:
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
            self.enc_objs.append(Encoding(name, encoding_str, fields, ne_fields, form))
        self.enc_objs = tuple(self.enc_objs)

    def __repr__(self):
        encs = "["+ ", ".join([inm for (inm,_,_,_,_) in self.encs]) +"]"
        return "Instruction{" + ", ".join([str(self.enc_objs), self.name])+"}"


########################################################################
# Extracting information from XML files
########################################################################

'''
Read pseudocode to extract an ASL name.
'''
def readASLName(ps):
    name = ps.attrib["name"]
    name = name.replace(".txt","")
    name = name.replace("/instrs","")
    name = name.replace("/Op_","/")

    return name

def readInstruction(xml):
    execs = xml.findall(".//pstext[@section='Execute']/..")
    assert(len(execs) <= 1)
    if not execs: return None # discard aliases

    exec_name = readASLName(execs[0])

    # for each encoding, read instructions encoding, matching decode ASL and index
    encs = []
    for iclass in xml.findall('.//classes/iclass'):
        encoding = iclass.find('regdiagram')
        form = encoding.attrib['form']
        isT16 = form == "16"
        insn_set = "T16" if isT16 else iclass.attrib['isa']

        ne_fields = []

        fields = []
        for b in encoding.findall('box'):
            wd = int(b.attrib.get('width','1'))
            hi = int(b.attrib['hibit'])
            # normalise T16 encoding bit numbers
            if isT16: hi = hi-16
            lo = hi - wd + 1
            nm  = b.attrib.get('name', '_')
            ignore = 'psbits' in b.attrib and b.attrib['psbits'] == 'x'*wd
            consts = ''.join([ 'x'*int(c.attrib.get('colspan','1')) if c.text is None or ignore else c.text for c in b.findall('c') ])

            # if adjacent entries are two parts of same field, join them
            # e.g., imm8<7:1> and imm8<0> or opcode[5:2] and opcode[1:0]
            m = re.match('^(\w+)[<[]', nm)
            if m:
                nm = m.group(1)
                split = True
                if fields[-1][3] and fields[-1][2] == nm:
                    (hi1,lo1,_,_,c1) = fields.pop()
                    assert(lo1 == hi+1) # must be adjacent
                    hi = hi1
                    consts = c1+consts
            else:
                split = False

            if consts.startswith('!= '):
                ne_fields.append((hi, lo, nm, split, consts[3:]))

            # discard != information because it is better obtained elsewhere in spec
            if consts.startswith('!= '): consts = 'x'*wd

            fields.append((hi,lo,nm,split,consts))

        # workaround: avoid use of overloaded field names
        fields2 = []
        for (hi, lo, nm, split, consts) in fields:
            if (nm in ["SP", "mask", "opcode"]
               and 'x' not in consts
               and exec_name not in ["aarch64/float/convert/fix", "aarch64/float/convert/int"]):
                # workaround: avoid use of overloaded field name
                nm = '_'
            fields2.append((hi,lo,nm,split,consts))

        dec_asl_name = readASLName(iclass.find('ps_section/ps'))

        name = dec_asl_name if insn_set in ["T16","T32","A32"] else encoding.attrib['psname']
        encs.append((name, insn_set, fields2, ne_fields, form))

    return Instruction(exec_name, encs)


def getInstrs(dirs, arches, verbose_level):
    encodings = []
    print("Arches: ", arches)
    if "AArch32" in arches: encodings.extend(["T16", "T32", "A32"])
    if "AArch64" in arches: encodings.extend(["A64"])
    if verbose_level > 0:
        if encodings != []:
            print("Selecting encodings", ", ".join(encodings))
        else:
            print("Selecting entire architecture")

    instrs = []
    for d in dirs:
        for inf in glob.glob(os.path.join(d, '*.xml')):
            name = re.search('.*/(\S+).xml',inf).group(1)
            if name == "onebigfile": continue
            xml = ET.parse(inf)
            instr = readInstruction(xml)
            if instr is None: continue

            if encodings != []: # discard encodings from unwanted InsnSets
                encs = tuple([ e for e in instr.encs if e[1] in encodings ])
                if encs == []:
                    if verbose_level > 1: print("Discarding", instr.name, encodings)
                    continue
                instr.encs = encs

            instrs.append(instr)

    return tuple(instrs)

########################################################################
# Main
########################################################################

def main():
    global instrs
    global instrs_encs
    global instrs_enc_objs

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', help='Use verbose output',
                        action = 'count', default=0)
    parser.add_argument('dir', metavar='<dir>',  nargs='+',
                        help='input directories')
    parser.add_argument('--arch', help='Optional list of architecture states to extract',
                        choices=["AArch32", "AArch64"], default=[], action='append')
    args = parser.parse_args()

    instrs = getInstrs(args.dir, args.arch, args.verbose)
    instrs_encs = tuple(itertools.chain(*(i.encs for i in instrs)))
    instrs_enc_objs = tuple(itertools.chain(*(i.enc_objs for i in instrs)))

    return

if __name__ == "__main__":
    sys.exit(main())

########################################################################
# End
########################################################################
