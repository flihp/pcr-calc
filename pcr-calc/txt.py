#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#
# module for interacting with stuff from TXT

import base64
import hashlib
import struct
import datetime

class acmFlags(object):
    def __init__(self, stuff):
        self._flags = stuff
    def DebugSigned(self):
        return bool (self._flags & 0b1000000000000000)
    def ProductionSigned(self):
        return not self.DebugSigned()
    def PreProduction(self):
        return bool (self._flags & 0b0100000000000000)
    def Production(self):
        return not self.PreProduction ()
    def Raw(self):
        return self._flags

class acmParse(object):
    def __init__(self, pfile):
        self._acmfile = pfile

    # "private" convenience functions
    def _read_bytes(self, offset, length):
        self._acmfile.seek (offset)
        inttup = struct.unpack ('<{0}B'.format(length),
                                self._acmfile.read (length))
        return bytearray (inttup)
    def _read_uint8(self, offset):
        self._acmfile.seek (offset)
        return struct.unpack ('<c', self._acmfile.read (1))[0]
    def _read_uint16(self, offset):
        self._acmfile.seek (offset)
        return struct.unpack ('<H', self._acmfile.read (2))[0]
    def _read_uint32(self, offset):
        self._acmfile.seek (offset)
        return struct.unpack ('<I', self._acmfile.read (4))[0]

    # public accessor functions
    def ModuleType(self):
        return self._read_uint16 (0)
    def ModuleSubType(self):
        return self._read_uint16 (2)
    def HeaderLen(self):
        return self._read_uint32 (4)
    def HeaderVersion(self):
        return self._read_uint32 (8)
    def ChipsetID(self):
        return self._read_uint16 (12)
    def Flags(self):
        return acmFlags (self._read_uint16 (14))
    def ModuleVendor(self):
        return self._read_uint32 (16)
    def Date(self):
        return self._read_uint32 (20)
    def DateObj(self):
        self._datebcd = self.Date ()
        # could not be less efficient, but seems to work
        _year = int (hex (self._datebcd >> 16)[2:])
        _month = int (hex ((self._datebcd >> 8) & 0x0000FF)[2:])
        _day = int (hex (self._datebcd & 0x000000F)[2:])
        return datetime.date (_year, _month, _day)
    def Size(self):
        return self._read_uint32 (24)
    def Reserved1(self):
        return self._read_uint32 (28)
    def CodeControl(self):
        return self._read_uint32 (32)
    def ErrorEntryPoint(self):
        return self._read_uint32 (36)
    def GDTLimit(self):
        return self._read_uint32 (40)
    def GDTBasePtr(self):
        return self._read_uint32 (44)
    def SegSel(self):
        return self._read_uint32 (48)
    def EntryPoint(self):
        return self._read_uint32 (52)
    def Reserved2(self):
        return self._read_bytes (56, 64)
    def KeySize(self):
        return self._read_uint32 (120)
    def ScratchSize(self):
        return self._read_uint32 (124)
    def RSAPubKey(self):
        return self._read_bytes (128, self.KeySize () * 4)
    def RSAPubExp(self):
        return self._read_uint32 (384)
    def RSASig(self):
        return self._read_bytes (388, 256)
    def Scratch(self):
        return self._read_bytes (644, self.ScratchSize () * 4)
    def UserArea(self):
        self._acmfile.seek(0, 2)
        acmsize = self._acmfile.tell ()
        start = 644 + self.ScratchSize () * 4
        return self._read_bytes (start, acmsize - start)

class pcrEmu(object):
    def __init__(self):
        self._value = base64.b16decode(b'00000000000000000000')
    def extend(self,something):
        _sha1 = hashlib.sha1 ()
        _sha1.update(self._value + something)
        self._value = _sha1.digest ()
    def read(self):
        return self._value
    def hexread(self):
        return self._value.encode("hex")
