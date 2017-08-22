#!/usr/bin/env python3

from future.utils import binary_type, text_type

from builtins import bytes
from builtins import range
from builtins import object
import os
import pickle
import struct

instr_dill_path = os.path.join(os.path.dirname(__file__), 'instr_encodings.pickle')


########################################################################
# Utility Functions
########################################################################

def is_thumb_inst_32_bit(inst):
    inst16 = None
    if isinstance(inst, binary_type):
        inst16 = struct.unpack('<H', inst[:2])[0]
    elif isinstance(inst, int):
        if inst & 0xFFFF0000:
            inst16 = inst & 0xFFFF
        else:
            inst16 = inst
    else:
        raise ValueError('Bad type: %s' % type(inst))
    if   inst16 & 0xF800 == 0xE000:  # B T2
        return False
    elif inst16 & 0xE000 == 0xE000:
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
        raise ValueError('Unhandled length: %d' % length)


def swap_endian_32_halfwords(n):
    return ((n & 0xFF000000) >> 24) << 16 | \
           ((n & 0x00FF0000) >> 16) << 24 | \
           ((n & 0x0000FF00) >>  8) <<  0 | \
           ((n & 0x000000FF) >>  0) <<  8


def hex_str(n, length=None):
    if isinstance(n, int) or isinstance(n, long):
        assert length is not None
        hex_strs = []
        for _ in range(length):
            hex_strs.append('%02X' % (n & 0xFF))
            n >>= 8
        return ' '.join(hex_strs)
    elif isinstance(n, binary_type):
        return ' '.join(['%02X' % b for b in bytes(n)])
    else:
        raise ValueError('Bad type: %s' % type(n))


########################################################################
# Classes
########################################################################

class Encoding(object):
    '''Representation of a particular Instruction Encoding'''

    def __init__(self, name, encoding_str, fields, ne_fields, form):
        self.name = name
        if encoding_str[0] == 'T' and encoding_str[0] != 'A':
            self.thumb = True
        elif encoding_str[0] == 'A' and encoding_str[0] != 'T':
            self.thumb = False
        else:
            raise ValueError("Can't decode ARM/Thumb from encoding '" + encoding_str + "'")
        if encoding_str[1:3] == '16':
            self.length = 2
        elif encoding_str[1:3] == '32' or encoding_str[1:3] == '64':
            self.length = 4
        else:
            raise ValueError("Bad encoding '" + encoding_str + "'")
        self.fields = fields
        self.ne_fields = ne_fields
        self.form = form

    def __eq__(self, other):
        if isinstance(other, binary_type):
            if self.length == 4 and len(other) >= 4:
                inst_int = struct.unpack('<I', other[:4])[0]
            elif self.length == 2 and len(other) >= 2:
                inst_int = struct.unpack('<H', other[:2])[0]
            else:
                raise ValueError('Bad length %d vs %d' % (self.length, len(other)))
        elif isinstance(other, Encoding):
            return self.name == other.name
        elif isinstance(other, int):
            inst_int = other
        else:
            raise ValueError('Bad type: %s' % type(other))

        if self.thumb and self.length == 4:
            inst_int = swap_endian(inst_int, 4)

        if self.bitmask() & inst_int == self.bitpattern():
            if self.ne_bitmask() != 0:
                if self.ne_bitmask() & inst_int != self.ne_bitpattern():
                    return True
                else:
                    return False
            return True
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def bitmask(self):
        mask = 0
        for field in self.fields:
            (bit_hi, bit_lo, _, _, bitstr) = field
            for bit_num in range(bit_lo, bit_hi + 1):
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
            for bit_num in range(bit_lo, bit_hi + 1):
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
            for bit_num in range(bit_lo, bit_hi + 1):
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
            for bit_num in range(bit_lo, bit_hi + 1):
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
        return "Enc[%s]{\n\tbitmask:\t%s\n\tbitpattern:\t%s\n\tne_bitmask:\t%s\n\t" \
               "ne_bitpattern:\t%s\n\tthumb:\t%d\n\tlength:\t%d\n\t" \
               "fields:\t%s\n\tne_fields:\t%s\n\tform:\t%s}" % \
               (self.name, bitmask_hex_str, bitpattern_hex_str, \
                ne_bitmask_hex_str, ne_bitpattern_hex_str, self.thumb, \
                self.length, self.fields, self.ne_fields, self.form)

class _Singleton(type):
    """ A metaclass that creates a Singleton base class when called. """
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Singleton(_Singleton('SingletonMeta', (object,), {})): pass

class Encodings(Singleton):
    def __init__(self):
        self.encs = pickle.load(open(instr_dill_path, 'rb'))

    def find_inst(self, inst, thumb):
        if isinstance(inst, text_type):
            for enc in self.encs:
                if enc.name != inst:
                    continue
                return enc
            return None

        length = get_inst_length(inst, thumb)

        for enc in self.encs:
            if enc.thumb != thumb:
                continue
            if enc.length != length:
                continue
            if enc != inst:
                continue
            return enc

        return None
