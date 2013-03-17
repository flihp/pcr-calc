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
    def __init__ (self, pfile, pmap=None):
        self._filemmap = pmap
    def _read_bytes_raw (self, offset, length):
        if self._filemmap:
            _tmp = self._filemmap [offset : offset + length]
        else:
            self._file.seek (self._offset + offset)
            _tmp = self._file.read (length)
        return _tmp
    def _read_bytes(self, offset, length):
        _tmp = self._read_bytes_raw (offset, length)
        inttup = struct.unpack ('<{0}B'.format(length), _tmp)
        return bytearray (inttup)
    def _read_uint8(self, offset):
        _tmp = self._read_bytes_raw (offset, 1)
        return struct.unpack ('<c', _tmp)[0]
    def _read_uint16(self, offset):
        _tmp = self._read_bytes_raw (offset, 2)
        return struct.unpack ('<H', _tmp)[0]
    def _read_uint32(self, offset):
        _tmp = self._read_bytes_raw (offset, 4)
        return struct.unpack ('<I', _tmp)[0]
    def _read_uint64(self,offset):
        _tmp = self._read_bytes_raw (offset, 8)
        return struct.unpack ('<Q', _tmp)[0]

class mapParse(binParse):
    def __init__(self, pfile, pmmap=False, poffset=0, psize=0):
        self._file = pfile
        self._offset = poffset
        self._map_size = psize
        try:
            self._file.seek (0,2)
            self._file_size = self._file.tell ()
            self._file.seek (0)
            self._filemmap = None
        except IOError as e:
            if not pmmap:
                raise IOError ('Cannot seek in file: {0}, mmap disabled.'.format (self._file.name));

        if pmmap:
            self._filemmap = mmap.mmap (self._file.fileno (),
                                        self._map_size,
                                        access=mmap.ACCESS_READ,
                                        offset=self._offset)
        super (mapParse, self).__init__ (self._file, self._filemmap)

class acmParse(mapParse):
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

class pubConfRegsParse(mapParse):
    _REG_SIZE = 8 # all regs are 64 bits per the spec
    _TXT_PUB_CONFIG_REGS_BASE = 0xfed30000
    _TXT_STS_OFFSET = 0x0
    _TXT_ESTS_OFFSET = 0x008
    _TXT_ERRORCODE_OFFSET = 0x030
    _TXT_CMD_RESET_OFFSET = 0x038
    _TXT_CMD_CLOSEPRIVATE_OFFSET = 0x048
    _TXT_VER_FSBIF_OFFSET = 0x100
    _TXT_DIDVID_OFFSET = 0x110
    _TXT_VER_QPIIF_OFFSET = 0x200
    _TXT_CMD_UNLOCKMEMCONFIG_OFFSET = 0x218
    _TXT_SINIT_BASE_OFFSET = 0x270
    _TXT_SINIT_SIZE_OFFSET = 0x278
    _TXT_MLE_JOIN_OFFSET = 0x290
    _TXT_HEAP_BASE_OFFSET = 0x300
    _TXT_HEAP_SIZE_OFFSET = 0x308
    _TXT_DPR_OFFSET = 0x330
    _TXT_CMD_OPEN_LOCALITY1_OFFSET = 0x380
    _TXT_CMD_CLOSE_LOCALITY1_OFFSET = 0x388
    _TXT_CMD_OPEN_LOCALITY2_OFFSET = 0x390
    _TXT_CMD_CLOSE_LOCALITY2_OFFSET = 0x398
    _TXT_PUBLIC_KEY_OFFSET = 0x400
    _TXT_CMD_SECRETS_OFFSET = 0x8e0
    _TXT_CMD_NOSECRETS_OFFSET = 0x8e8
    _TXT_E2STS_OFFSET = 0xef0
    def __init__(self, pfile, pmmap=False, from_mem=False):
        self._mmap = pmmap
        self._offset = 0
        self._size = (self._TXT_E2STS_OFFSET + self._REG_SIZE) - self._TXT_STS_OFFSET
        if from_mem:
            self._offset = self._TXT_PUB_CONFIG_REGS_BASE
        print 'mapping TXT public config registers from offset {0}, size {1}'.format (hex (self._offset), hex (self._size))
        super (pubConfRegsParse, self).__init__ (pfile, pmmap, poffset=self._offset, psize=self._size)
    # readable config registers
    def Status (self):
        return self._read_uint64 (self._TXT_STS_OFFSET)
    def ErrorStatus (self):
        return self._read_uint64 (self._TXT_ESTS_OFFSET)
    def ErrorCode (self):
        return self._read_uint64 (self._TXT_ERRORCODE_OFFSET)
    def FSBInterface (self):
        return self._read_uint64 (self._TXT_VER_FSBIF_OFFSET)
    def DeviceID (self):
        return self._read_uint64 (self._TXT_DIDVID_OFFSET)
    def QuickPath (self):
        return self._read_uint64 (self._TXT_VER_QPIIF_OFFSET)
    def SINITBase (self):
        return self._read_uint64 (self._TXT_SINIT_BASE_OFFSET)
    def SINITSize (self):
        return self._read_uint64 (self._TXT_SINIT_SIZE_OFFSET)
    def MLEJoinBase (self):
        return self._read_uint64 (self._TXT_MLE_JOIN_OFFSET)
    def HeapBase (self):
        return self._read_uint64 (self._TXT_HEAP_BASE_OFFSET)
    def HeapSize (self):
        return self._read_uint64 (self._TXT_HEAP_SIZE_OFFSET)
    def DMAProtected (self):
        return self._read_uint64 (self._TXT_DPR_OFFSET)
    def PublicKey_Bytes (self):
        _bytes = self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET, 8)
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 8, 8))
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 16, 8))
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 24, 8))
        return _bytes
    def ExtErrorStatus (self):
        return self._read_uint64 (self._TXT_E2STS_OFFSET)

class txtHeap (mapParse):
    _BIOS_DATA_SIZE_OFFSET = 0x0
    _BIOS_DATA_SIZE_LENGTH = 0x8
    _BIOS_DATA_OFFSET = _BIOS_DATA_SIZE_LENGTH
    _OS_MLE_DATA_SIZE_LENGTH = 0x8
    _OS_SINIT_DATA_SIZE_LENGTH = 0x8
    _SINIT_MLE_DATA_SIZE_LENGTH = 0x8
    # need size from heap
    # _BIOS_DATA_OFFSET = _BIOS_DATA_SIZE_LENGTH + BiosDataSize ()
    def __init__(self, pfile, pmmap=False, offset=0x0, size=0x0):
        self._mmap = pmmap
        self._offset = offset
        self._size = size
        print 'mapping TXT heap at offset {0}, length {1}'.format (hex (self._offset), hex (self._size))
        super (txtHeap, self).__init__ (pfile, pmmap, poffset=self._offset, psize=self._size)
    def _OsMleDataOffset (self):
        return self.BiosDataSize () + self._BIOS_DATA_SIZE_LENGTH
    def _OsSinitDataOffset (self):
        return self.BiosDataSize () + self.OsMleDataSize () + self._OS_SINIT_DATA_SIZE_LENGTH
    def _SinitMleDataOffset (self):
        return self.BiosDataSize () + self.OsMleDataSize () + self.OsSinitDataSize () + self._SINIT_MLE_DATA_SIZE_LENGTH

    def Bytes (self):
        return self._read_bytes (self._BIOS_DATA_SIZE_OFFSET, self.HeapLength ())
    def BiosDataSize (self):
        return self._read_uint64 (self._BIOS_DATA_SIZE_OFFSET)
    def BiosData (self):
        return self._read_bytes (self._BIOS_DATA_OFFSET, self.BiosDataSize () - self._BIOS_DATA_SIZE_LENGTH)
    def OsMleDataSize (self):
        return self._read_uint64 (self.BiosDataSize ())
    def OsMleData (self):
        return self._read_bytes (self._OsMleDataOffset (), self.OsMleDataSize () - self._OS_MLE_DATA_SIZE_LENGTH)
    def OsSinitDataSize (self):
        return self._read_uint64 (self.BiosDataSize () + self.OsMleDataSize ())
    def OsSinitData (self):
        return self._read_bytes (self._OsSinitDataOffset (), self.OsSinitDataSize () - self._OS_SINIT_DATA_SIZE_LENGTH)
    def SinitMleDataSize (self):
        return self._read_uint64 (self.BiosDataSize () + self.OsMleDataSize () + self.OsSinitDataSize ())
    def SinitMleData (self):
        return self._read_bytes (self._SinitMleDataOffset (), self.SinitMleDataSize () - self._SINIT_MLE_DATA_SIZE_LENGTH)
    def HeapLength (self):
        return self.BiosDataSize () + self.OsMleDataSize () + self.OsSinitDataSize () + self.SinitMleDataSize ()

class sinitMleData (binParse):
    _VERSION_OFFSET = 0
    _VERSION_LENGTH = 4
    _BIOS_ACM_ID_OFFSET = _VERSION_OFFSET + _VERSION_LENGTH
    _BIOS_ACM_ID_LENGTH = 20
    _EDX_SENTER_FLAGS_OFFSET = _BIOS_ACM_ID_OFFSET + _BIOS_ACM_ID_LENGTH
    _EDX_SENTER_FLAGS_LENGTH = 4
    _MSEG_VALID_OFFSET = _EDX_SENTER_FLAGS_OFFSET + _EDX_SENTER_FLAGS_LENGTH
    _MSEG_VALID_LENGTH = 8
    _SINIT_HASH_OFFSET = _MSEG_VALID_OFFSET + _MSEG_VALID_LENGTH
    _SINIT_HASH_LENGTH = 20
    _MLE_HASH_OFFSET = _SINIT_HASH_OFFSET + _SINIT_HASH_LENGTH
    _MLE_HASH_LENGTH = 20
    _STM_HASH_OFFSET = _MLE_HASH_OFFSET + _MLE_HASH_LENGTH
    _STM_HASH_LENGTH = 20
    _LCP_POLICY_HASH_OFFSET = _STM_HASH_OFFSET + _STM_HASH_LENGTH
    _LCP_POLICY_HASH_LENGTH = 20
    _POLICY_CONTROL_OFFSET = _LCP_POLICY_HASH_OFFSET + _LCP_POLICY_HASH_LENGTH
    _POLICY_CONTROL_LENGTH = 4
    _RLP_WAKEUP_ADDR_OFFSET = _POLICY_CONTROL_OFFSET + _POLICY_CONTROL_LENGTH
    _RLP_WAKEUP_ADDR_LENGTH = 4
    _RESERVED_OFFSET = _RLP_WAKEUP_ADDR_OFFSET + _RLP_WAKEUP_ADDR_LENGTH
    _RESERVED_LENGTH = 4
    _NUMBER_SINIT_MDRS_OFFSET = _RESERVED_OFFSET + _RESERVED_LENGTH
    _NUMBER_SINIT_MDRS_LENGTH = 4
    _SINIT_MDR_TABLE_OFFSET_OFFSET = _NUMBER_SINIT_MDRS_OFFSET + _NUMBER_SINIT_MDRS_LENGTH
    _SINIT_MDR_TABLE_OFFSET_LENGTH = 4
    _SINIT_VTD_DMAR_TABLE_SIZE_OFFSET = _SINIT_MDR_TABLE_OFFSET_OFFSET + _SINIT_MDR_TABLE_OFFSET_LENGTH
    _SINIT_VTD_DMAR_TABLE_SIZE_LENGTH = 4
    _SINIT_VTD_DMAR_TABLE_OFFSET_OFFSET = _SINIT_VTD_DMAR_TABLE_SIZE_OFFSET + _SINIT_VTD_DMAR_TABLE_SIZE_LENGTH
    _SINIT_VTD_DMAR_TABLE_OFFSET_LENGTH = 4
    _PROCESSOR_SCRTM_STATUS_OFFSET = _SINIT_VTD_DMAR_TABLE_OFFSET_OFFSET + _SINIT_VTD_DMAR_TABLE_OFFSET_LENGTH
    _PROCESSOR_SCRTM_STATUS_LENGTH = 4
    def __init__(self, pbytes):
        super (sinitMleData, self).__init__ (None, str (pbytes))
    def Bytes (self):
        return self._read_bytes (self._VERSION_OFFSET, self._PROCESSOR_SCRTM_STATUS_OFFSET + self._PROCESSOR_SCRTM_STATUS_LENGTH)
    def Version (self):
        return self._read_uint32 (self._VERSION_OFFSET)
    def BiosAcmId (self):
        return self._read_bytes (self._BIOS_ACM_ID_OFFSET, self._BIOS_ACM_ID_LENGTH)
    def EdxSenterFlags (self):
        return self._read_uint32 (self._EDX_SENTER_FLAGS_OFFSET)
    def MsegValid (self):
        return self._read_uint64 (self._MSEG_VALID_OFFSET)
    def SinitHash (self):
        return self._read_bytes (self._SINIT_HASH_OFFSET, self._SINIT_HASH_LENGTH)
    def LcpPolicyHash (self):
        return self._read_bytes (self._LCP_POLICY_HASH_OFFSET, self._LCP_POLICY_HASH_LENGTH)
    def PolicyControl (self):
        return self._read_uint32 (self._POLICY_CONTROL_OFFSET)
    def RlpWakeupAddr (self):
        return self._read_uint32 (self._RLP_WAKEUP_ADDR_OFFSET)
    def Reserved (self):
        return self._read_uint32 (self._RESERVED_OFFSET)
    def NumSinitMdrs (self):
        return self._read_uint32 (self._NUMBER_SINIT_MDRS_OFFSET)
    def SinitMdrTableOffset (self):
        return self._read_uint32 (self._SINIT_MDR_TABLE_OFFSET_OFFSET)
    def SinitVtdDmarTableSize (self):
        return self._read_uint32 (self._SINIT_VTD_DMAR_TABLE_SIZE_OFFSET)
    def SinitVtdDmarTableOffset (self):
        return self._read_uint32 (self._SINIT_VTD_DMAR_TABLE_OFFSET_OFFSET)
    def ProcScrtmStatus (self):
        return self._read_uint32 (self._PROCESSOR_SCRTM_STATUS_OFFSET)

class osSinitData (binParse):
    _VERSION_OFFSET = 0
    _VERSION_LENGTH = 4
    _RESERVED_OFFSET = _VERSION_OFFSET + _VERSION_LENGTH
    _RESERVED_LENGTH = 4
    _MLE_PAGETABLE_BASE_OFFSET = _RESERVED_OFFSET + _RESERVED_LENGTH
    _MLE_PAGETABLE_BASE_LENGTH = 8
    _MLE_SIZE_OFFSET = _MLE_PAGETABLE_BASE_OFFSET + _MLE_PAGETABLE_BASE_LENGTH
    _MLE_SIZE_LENGTH = 8
    _MLE_HEADER_BASE_OFFSET = _MLE_SIZE_OFFSET + _MLE_SIZE_LENGTH
    _MLE_HEADER_BASE_LENGTH = 8
    _PMR_LOW_BASE_OFFSET = _MLE_HEADER_BASE_OFFSET + _MLE_HEADER_BASE_LENGTH
    _PMR_LOW_BASE_LENGTH = 8
    _PMR_LOW_SIZE_OFFSET = _PMR_LOW_BASE_OFFSET + _PMR_LOW_BASE_LENGTH
    _PMR_LOW_SIZE_LENGTH = 8
    _PMR_HIGH_BASE_OFFSET = _PMR_LOW_SIZE_OFFSET + _PMR_LOW_SIZE_LENGTH
    _PMR_HIGH_BASE_LENGTH = 8
    _PMR_HIGH_SIZE_OFFSET = _PMR_HIGH_BASE_OFFSET + _PMR_HIGH_BASE_LENGTH
    _PMR_HIGH_SIZE_LENGTH = 8
    _LCP_PO_BASE_OFFSET = _PMR_HIGH_SIZE_OFFSET + _PMR_HIGH_SIZE_LENGTH
    _LCP_PO_BASE_LENGTH = 8
    _LCP_PO_SIZE_OFFSET = _LCP_PO_BASE_OFFSET + _LCP_PO_BASE_LENGTH
    _LCP_PO_SIZE_LENGTH = 8
    _CAPABILITIES_OFFSET = _LCP_PO_SIZE_OFFSET + _LCP_PO_SIZE_LENGTH
    _CAPABILITIES_LENGTH = 4
    _EFI_RSDT_POINTER_OFFSET = _CAPABILITIES_OFFSET + _CAPABILITIES_LENGTH
    _EFI_RSDT_POINTER_LENGTH = 8
    def __init__(self, pbytes):
        super (osSinitData, self).__init__ (None, str (pbytes))
    def Version (self):
        return self._read_uint32 (self._VERSION_OFFSET)
    def MlePageTableBase (self):
        return self._read_uint64 (self._MLE_PAGETABLE_BASE_OFFSET)
    def MleSize (self):
        return self._read_uint64 (self._MLE_SIZE_OFFSET)
    def MleHeaderBase (self):
        return self._read_uint64 (self._MLE_HEADER_BASE_OFFSET)
    def PmrLowBase (self):
        return self._read_uint64 (self._PMR_LOW_BASE_OFFSET)
    def PmrLowSize (self):
        return self._read_uint64 (self._PMR_LOW_SIZE_OFFSET)
    def PmrHighBase (self):
        return self._read_uint64 (self._PMR_HIGH_BASE_OFFSET)
    def PmrHighSize (self):
        return self._read_uint64 (self._PMR_HIGH_SIZE_OFFSET)
    def LcpPoBase (self):
        return self._read_uint64 (self._LCP_PO_BASE_OFFSET)
    def LcpPoSize (self):
        return self._read_uint64 (self._LCP_PO_SIZE_OFFSET)
    def Capabilities (self):
        return self._read_uint32 (self._CAPABILITIES_OFFSET)
    def EfiRsdtPointer (self):
        return self._read_uint64 (self._EFI_RSDT_POINTER_OFFSET)
        
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
