#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#
# module for interacting with stuff from TXT

import base64
import hashlib
import struct
import datetime
import mmap

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

class binParse(object):
    def __init__(self, pfile, dommap=False):
        self._file = pfile
        self._file.seek (0,2)
        self._file_size = self._file.tell ()
        self._file.seek (0)
        self._filemmap = None
        if dommap:
            self._filemmap = mmap.mmap (self._file.fileno (), 0, access=mmap.ACCESS_READ)

    # "private" convenience functions
    def _read_bytes(self, offset, length):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + length]
        else:
            self._file.seek (offset)
            _tmp = self._file.read (length)
        inttup = struct.unpack ('<{0}B'.format(length), _tmp)
        return bytearray (inttup)
    def _read_uint8(self, offset):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + 11]
        else:
            self._file.seek (offset)
            _tmp = self._file.read (1)
        return struct.unpack ('<c', _tmp)[0]
    def _read_uint16(self, offset):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + 2]
        else:
            self._file.seek (offset)
            _tmp = self._file.read (2)
        return struct.unpack ('<H', _tmp)[0]
    def _read_uint32(self, offset):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + 4]
        else:
            self._file.seek (offset)
            _tmp = self._file.read (4)
        return struct.unpack ('<I', _tmp)[0]
    def _read_unit64(self,offset):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + 8]
        else:
            self._file.seek (offset)
            _tmp = self._file.read (8)
        return struct.unpack ('<Q', _tmp)[0]

class acmParse(binParse):
    # offsets & sizes from MLE dev guide appendix A.1, table 3
    _MODULE_TYPE_OFFSET = 0
    _MODULE_TYPE_SIZE = 2
    _MODULE_SUBTYPE_OFFSET = _MODULE_TYPE_OFFSET + _MODULE_TYPE_SIZE
    _MODULE_SUBTYPE_SIZE = 2
    _HEADER_LENGTH_OFFSET = _MODULE_SUBTYPE_OFFSET + _MODULE_SUBTYPE_SIZE
    _HEADER_LENGTH_SIZE = 4
    _HEADER_VERSION_OFFSET = _HEADER_LENGTH_OFFSET + _HEADER_LENGTH_SIZE
    _HEADER_VERSION_SIZE = 4
    _CHIPSET_ID_OFFSET = _HEADER_VERSION_OFFSET + _HEADER_VERSION_SIZE
    _CHIPSET_ID_SIZE = 2
    _FLAGS_OFFSET = _CHIPSET_ID_OFFSET + _CHIPSET_ID_SIZE
    _FLAGS_SIZE = 2
    _MODULE_VENDOR_OFFSET = _FLAGS_OFFSET + _FLAGS_SIZE
    _MODULE_VENDOR_SIZE = 4
    _DATE_OFFSET = _MODULE_VENDOR_OFFSET + _MODULE_VENDOR_SIZE
    _DATE_SIZE = 4
    _MODULE_SIZE_OFFSET = _DATE_OFFSET + _DATE_SIZE
    _MODULE_SIZE_SIZE = 4
    _RESERVED1_OFFSET = _MODULE_SIZE_OFFSET + _MODULE_SIZE_SIZE
    _RESERVED1_SIZE = 4
    _CODE_CONTROL_OFFSET = _RESERVED1_OFFSET + _RESERVED1_SIZE
    _CODE_CONTROL_SIZE = 4
    _ERROR_ENTRY_POINT_OFFSET = _CODE_CONTROL_OFFSET + _CODE_CONTROL_SIZE
    _ERROR_ENTRY_POINT_SIZE = 4
    _GDT_LIMIT_OFFSET = _ERROR_ENTRY_POINT_OFFSET + _ERROR_ENTRY_POINT_SIZE
    _GDT_LIMIT_SIZE = 4
    _GDT_BASE_PTR_OFFSET = _GDT_LIMIT_OFFSET + _GDT_LIMIT_SIZE
    _GDT_BASE_PTR_SIZE = 4
    _SEGMENT_SELECTOR_OFFSET = _GDT_BASE_PTR_OFFSET + _GDT_BASE_PTR_SIZE
    _SEGMENT_SELECTOR_SIZE = 4
    _ENTRY_POINT_OFFSET = _SEGMENT_SELECTOR_OFFSET + _SEGMENT_SELECTOR_SIZE
    _ENTRY_POINT_SIZE = 4
    _RESERVED2_OFFSET = _ENTRY_POINT_OFFSET + _ENTRY_POINT_SIZE
    _RESERVED2_SIZE = 64
    _KEY_SIZE_OFFSET = _RESERVED2_OFFSET + _RESERVED2_SIZE
    _KEY_SIZE_SIZE = 4
    _SCRATCH_SIZE_OFFSET = _KEY_SIZE_OFFSET + _KEY_SIZE_SIZE
    _SCRATCH_SIZE_SIZE = 4
    _RSA_PUBKEY_OFFSET = _SCRATCH_SIZE_OFFSET + _SCRATCH_SIZE_SIZE
    # need to know _KEY_SIZE to calculate RSA_PUBKEY_SIZE
    _RSA_PUBEXP_OFFSET = 384
    _RSA_PUBEXP_SIZE = 4
    _RSA_SIG_OFFSET = _RSA_PUBEXP_OFFSET + _RSA_PUBEXP_SIZE
    _RSA_SIG_SIZE = 256
    _SCRATCH_OFFSET = _RSA_SIG_OFFSET + _RSA_SIG_SIZE
    # need to know scratch size and file size to calculate UserArea stuff

    def __init__ (self, pfile, pmmap=False):
        super (acmParse, self).__init__ (pfile, pmmap)

    # public accessor functions
    def ModuleType(self):
        return self._read_uint16 (self._MODULE_TYPE_OFFSET)
    def ModuleType_Bytes(self):
        return self._read_bytes (self._MODULE_TYPE_OFFSET, self._MODULE_TYPE_SIZE)
    def ModuleSubType(self):
        return self._read_uint16 (self._MODULE_SUBTYPE_OFFSET)
    def ModuleSubType_Bytes(self):
        return self._read_bytes (self._MODULE_SUBTYPE_OFFSET, self._MODULE_SUBTYPE_OFFSET)
    def HeaderLen(self):
        return self._read_uint32 (self._HEADER_LENGTH_OFFSET)
    def HeaderLen_Bytes(self):
        return self._read_bytes (self._HEADER_LENGTH_OFFSET, self._HEADER_LENGTH_SIZE)
    def HeaderVersion(self):
        return self._read_uint32 (self._HEADER_VERSION_OFFSET)
    def HeaderVersion_Bytes(self):
        return self._read_bytes (self._HEADER_VERSION_OFFSET, self._HEADER_VERSION_SIZE)
    def ChipsetID(self):
        return self._read_uint16 (self._CHIPSET_ID_OFFSET)
    def ChipsetID_Bytes(self):
        return self._read_bytes (self._CHIPSET_ID_OFFSET, self._CHIPSET_ID_SIZE)
    def Flags(self):
        return acmFlags (self._read_uint16 (self._FLAGS_OFFSET))
    def Flags_Bytes(self):
        return self._read_bytes (self._FLAGS_OFFSET, self._FLAGS_SIZE)
    def ModuleVendor(self):
        return self._read_uint32 (self._MODULE_VENDOR_OFFSET)
    def ModuleVendor_Bytes(self):
        return self._read_bytes (self._MODULE_VENDOR_OFFSET, self._MODULE_VENDOR_SIZE)
    def Date(self):
        return self._read_uint32 (self._DATE_OFFSET)
    def DateObj(self):
        self._datebcd = self.Date ()
        _year = int (hex (self._datebcd >> 16)[2:])
        _month = int (hex ((self._datebcd >> 8) & 0x0000FF)[2:])
        _day = int (hex (self._datebcd & 0x000000F)[2:])
        return datetime.date (_year, _month, _day)
    def Date_Bytes(self):
        return self._read_bytes (self._DATE_OFFSET, self._DATE_SIZE)
    def Size(self):
        return self._read_uint32 (self._MODULE_SIZE_OFFSET)
    def Size_Bytes(self):
        return self._read_bytes (self._MODULE_SIZE_OFFSET, self._MODULE_SIZE_SIZE)
    def Reserved1(self):
        return self._read_uint32 (self._RESERVED1_OFFSET)
    def Reserved1_Bytes(self):
        return self._read_bytes (self._RESERVED1_OFFSET, self._RESERVED1_SIZE)
    def CodeControl(self):
        return self._read_uint32 (self._CODE_CONTROL_OFFSET)
    def CodeControl_Bytes(self):
        return self._read_bytes (self._CODE_CONTROL_OFFSET, self._CODE_CONTROL_SIZE)
    def ErrorEntryPoint(self):
        return self._read_uint32 (self._ERROR_ENTRY_POINT_OFFSET)
    def ErrorEntryPoint_Bytes(self):
        return self._read_bytes (self._ERROR_ENTRY_POINT_OFFSET, self._ERROR_ENTRY_POINT_SIZE)
    def GDTLimit(self):
        return self._read_uint32 (self._GDT_LIMIT_OFFSET)
    def GDTLimit_Bytes(self):
        return self._read_bytes (self._GDT_LIMIT_OFFSET, self._GDT_LIMIT_SIZE)
    def GDTBasePtr(self):
        return self._read_uint32 (self._GDT_BASE_PTR_OFFSET)
    def GDTBasePtr_Bytes(self):
        return self._read_bytes (self._GDT_BASE_PTR_OFFSET, self._GDT_BASE_PTR_SIZE)
    def SegSel(self):
        return self._read_uint32 (self._SEGMENT_SELECTOR_OFFSET)
    def SegSel_Bytes(self):
        return self._read_bytes (self._SEGMENT_SELECTOR_OFFSET, self._SEGMENT_SELECTOR_SIZE)
    def EntryPoint(self):
        return self._read_uint32 (self._ENTRY_POINT_OFFSET)
    def EntryPoint_Bytes(self):
        return self._read_bytes (self._ENTRY_POINT_OFFSET, self._ENTRY_POINT_SIZE)
    def Reserved2(self):
        return self._read_bytes (self._RESERVED2_OFFSET, self._RESERVED2_SIZE)
    def KeySize(self):
        return self._read_uint32 (self._KEY_SIZE_OFFSET)
    def KeySize_Bytes(self):
        return self._read_bytes (self._KEY_SIZE_OFFSET, self._KEY_SIZE_SIZE)
    def ScratchSize(self):
        return self._read_uint32 (self._SCRATCH_SIZE_OFFSET)
    def ScratchSize_Bytes(self):
        return self._read_bytes (self._SCRATCH_SIZE_OFFSET, self._SCRATCH_SIZE_SIZE)
    def RSAPubKey(self):
        return self._read_bytes (self._RSA_PUBKEY_OFFSET,
                                 self.KeySize () * 4)
    def RSAPubExp(self):
        return self._read_uint32 (self._RSA_PUBEXP_OFFSET)
    def RSAPubExp_Bytes(self):
        return self._read_bytes (self._RSA_PUBEXP_OFFSET, self._RSA_PUBEXP_SIZE)
    def RSASig(self):
        return self._read_bytes (self._RSA_SIG_OFFSET, self._RSA_SIG_SIZE)
    def Scratch(self):
        return self._read_bytes (self._SCRATCH_OFFSET, self.ScratchSize () * 4)
    def UserArea(self):
        _userarea_offset = self._SCRATCH_OFFSET + (self.ScratchSize () * 4)
        _userarea_size = self._file_size - _userarea_offset
        return self._read_bytes (_userarea_offset, _userarea_size)

class txtHeap(binParse):
    def __init__ (self, pfile, pbase, psize):
        super (txtHeap, self).__init__ (pfile, False)
        self._base = pbase
        self._size = psize
    def BiosDataSize (self):
        return self._read_uint64 (self._base)

class pubConfRegsParse(binParse):
    def __init__(self, pfile, from_mem=True):
        super (pubConfRegsParse, self).__init__ (pfile, False)
        if from_mem:
            self._TXT_PUB_CONFIG_REGS_BASE = 0xfed30000
        else:
            self._TXT_PUB_CONFIG_REGS_BASE = 0x0
        self._HEAP_BASE_OFFSET = self._TXT_PUB_CONFIG_REGS_BASE + 0x300
        self._HEAP_SIZE_OFFSET = self._TXT_PUB_CONFIG_REGS_BASE + 0x308
    def HeapBase (self):
        return self._read_uint32 (self._HEAP_BASE_OFFSET)
    def HeapSize (self):
        return self._read_uint32 (self._HEAP_SIZE_OFFSET)
    def Heap (self):
        return txtHeap (self._file, self.HeapBase (), self.HeapSize ())
    def HeapBytes (self):
        return self._read_bytes (self.HeapBase (), self.HeapSize ())

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
