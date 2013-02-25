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
    # ModuleType is 2 bytes at offset 0
    def ModuleType(self):
        return self._read_uint16 (0)
    def ModuleType_Bytes(self):
        return self._read_bytes (0, 2)
    # ModuleSubType is 2 bytes at offset 2
    def ModuleSubType(self):
        return self._read_uint16 (2)
    def ModuleSubType_Bytes(self):
        return self._read_bytes (2, 2)
    # HeaderLen is 4 bytes at offset 4
    def HeaderLen(self):
        return self._read_uint32 (4)
    def HeaderLen_Bytes(self):
        return self._read_bytes (4, 4)
    # HeaderVersion is 4 bytes at offset 8
    def HeaderVersion(self):
        return self._read_uint32 (8)
    def HeaderVersion_Bytes(self):
        return self._read_bytes (8, 4)
    # ChipsetID is 2 bytes at offset 12
    def ChipsetID(self):
        return self._read_uint16 (12)
    def ChipsetID_Bytes(self):
        return self._read_bytes (12, 2)
    # Flags are 2 bytes at offset 14
    def Flags(self):
        return acmFlags (self._read_uint16 (14))
    def Flags_Bytes(self):
        return self._read_bytes (14, 2)
    # ModuleVendor is 4 bytes at offset 16
    def ModuleVendor(self):
        return self._read_uint32 (16)
    def ModuleVendor_Bytes(self):
        return self._read_bytes (16, 4)
    # Date is 4 bytes at offset 20
    def Date(self):
        return self._read_uint32 (20)
    def DateObj(self):
        self._datebcd = self.Date ()
        # could not be less efficient, but seems to work
        _year = int (hex (self._datebcd >> 16)[2:])
        _month = int (hex ((self._datebcd >> 8) & 0x0000FF)[2:])
        _day = int (hex (self._datebcd & 0x000000F)[2:])
        return datetime.date (_year, _month, _day)
    def Date_Bytes(self):
        return self._read_bytes (20, 4)
    # Size is 4 bytes at offset 24
    def Size(self):
        return self._read_uint32 (24)
    def Size_Bytes(self):
        return self._read_bytes (24, 4)
    # Reserved1 is 4 bytes at offset 28
    def Reserved1(self):
        return self._read_uint32 (28)
    def Reserved1_Bytes(self):
        return self._read_bytes (28, 4)
    # CodeControl is 4 bytes at offset 32
    def CodeControl(self):
        return self._read_uint32 (32)
    def CodeControl_Bytes(self):
        return self._read_bytes (32, 4)
    # ErrorEntryPoint is 4 bytes at offset 36
    def ErrorEntryPoint(self):
        return self._read_uint32 (36)
    def ErrorEntryPoint_Bytes(self):
        return self._read_bytes (36, 4)
    # GDTLimit is 4 bytes at offset 40
    def GDTLimit(self):
        return self._read_uint32 (40)
    def GDTLimit_Bytes(self):
        return self._read_bytes (40, 4)
    # GDTBasePtr is 4 bytes at offset 44
    def GDTBasePtr(self):
        return self._read_uint32 (44)
    def GDTBasePtr_Bytes(self):
        return self._read_bytes (44, 4)
    # SegSel is 4 bytes at offset 48
    def SegSel(self):
        return self._read_uint32 (48)
    def SegSel_Bytes(self):
        return self._read_bytes (48, 4)
    # EntryPoint is 4 bytes at offset 52
    def EntryPoint(self):
        return self._read_uint32 (52)
    def EntryPoint_Bytes(self):
        return self._read_bytes (52, 4)
    # Reserved2 is 64 bytes at offset 56
    def Reserved2(self):
        return self._read_bytes (56, 64)
    # KeySize is 4 bytes at offset 120
    def KeySize(self):
        return self._read_uint32 (120)
    def KeySize_Bytes(self):
        return self._read_bytes (120, 4)
    # ScratchSize is 4 bytes at offset 124
    def ScratchSize(self):
        return self._read_uint32 (124)
    def ScratchSize_Bytes(self):
        return self._read_bytes (124, 4)
    # RSAPubKey is KeySize * 4 bytes at offset 128
    def RSAPubKey(self):
        return self._read_bytes (128, self.KeySize () * 4)
    # RSAPubExp is 4 bytes at offset 384
    def RSAPubExp(self):
        return self._read_uint32 (384)
    def RSAPubExp_Bytes(self):
        return self._read_bytes (384, 4)
    # RSASig is 256 bytes at offset 388
    def RSASig(self):
        return self._read_bytes (388, 256)
    # Scratch is ScratchSize * 4 bytes at offset 644
    def Scratch(self):
        return self._read_bytes (644, self.ScratchSize () * 4)
    # UserArea is the rest of the file starting at offset 644 + ScratchSize * 4
    def UserArea(self):
        self._acmfile.seek(0, 2)
        acmsize = self._acmfile.tell ()
        start = 644 + self.ScratchSize () * 4
        return self._read_bytes (start, acmsize - start)

class pcrEmu(object):
    def __init__(self):
        self._value = base64.b16decode(''.join('00' for x in range (0, hashlib.sha1 ().digest_size)))
    def extend(self,something):
        _sha1 = hashlib.sha1 ()
        _sha1.update(self._value + something)
        self._value = _sha1.digest ()
    def read(self):
        return self._value
    def hexread(self):
        return self._value.encode("hex")
