#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#
# module for interacting with stuff from TXT

import base64
import hashlib
import struct
import datetime
import mmap
import uuid

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
        self._unpack_int = {
            1 : self._unpack_uint8,
            2 : self._unpack_uint16,
            4 : self._unpack_uint32,
            8 : self._unpack_uint64,
            }
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
    def _read_uint (self, offset, length):
        _tmp = self._read_bytes_raw (offset, length)
        return self._unpack_int [length] (_tmp)
    def _unpack_uint8 (self, data):
        return struct.unpack ('<c', data)[0]
    def _unpack_uint16 (self, data):
        return struct.unpack ('<H', data)[0]
    def _unpack_uint32 (self, data):
        return struct.unpack ('<I', data)[0]
    def _unpack_uint64 (self, data):
        return struct.unpack ('<Q', data)[0]

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

    def __init__ (self, pfile, pmmap=False, sinitmledtv=8):
        super (acmParse, self).__init__ (pfile, pmmap)
        self._sinit_mle_dtv = sinitmledtv

    # public accessor functions
    def ModuleType(self):
        return self._read_uint (self._MODULE_TYPE_OFFSET, self._MODULE_TYPE_SIZE)
    def ModuleType_Bytes(self):
        return self._read_bytes (self._MODULE_TYPE_OFFSET, self._MODULE_TYPE_SIZE)
    def ModuleSubType(self):
        return self._read_uint (self._MODULE_SUBTYPE_OFFSET, self._MODULE_SUBTYPE_SIZE)
    def ModuleSubType_Bytes(self):
        return self._read_bytes (self._MODULE_SUBTYPE_OFFSET, self._MODULE_SUBTYPE_OFFSET)
    def HeaderLen(self):
        return self._read_uint (self._HEADER_LENGTH_OFFSET, self._HEADER_LENGTH_SIZE)
    def HeaderLen_Bytes(self):
        return self._read_bytes (self._HEADER_LENGTH_OFFSET, self._HEADER_LENGTH_SIZE)
    def HeaderVersion(self):
        return self._read_uint (self._HEADER_VERSION_OFFSET, self._HEADER_VERSION_SIZE)
    def HeaderVersion_Bytes(self):
        return self._read_bytes (self._HEADER_VERSION_OFFSET, self._HEADER_VERSION_SIZE)
    def ChipsetID(self):
        return self._read_uint (self._CHIPSET_ID_OFFSET, self._CHIPSET_ID_SIZE)
    def ChipsetID_Bytes(self):
        return self._read_bytes (self._CHIPSET_ID_OFFSET, self._CHIPSET_ID_SIZE)
    def Flags(self):
        return acmFlags (self._read_uint (self._FLAGS_OFFSET, self._FLAGS_SIZE))
    def Flags_Bytes(self):
        return self._read_bytes (self._FLAGS_OFFSET, self._FLAGS_SIZE)
    def ModuleVendor(self):
        return self._read_uint (self._MODULE_VENDOR_OFFSET, self._MODULE_VENDOR_SIZE)
    def ModuleVendor_Bytes(self):
        return self._read_bytes (self._MODULE_VENDOR_OFFSET, self._MODULE_VENDOR_SIZE)
    def Date(self):
        return self._read_uint (self._DATE_OFFSET, self._DATE_SIZE)
    def DateObj(self):
        self._datebcd = self.Date ()
        _year = int (hex (self._datebcd >> 16)[2:])
        _month = int (hex ((self._datebcd >> 8) & 0x0000FF)[2:])
        _day = int (hex (self._datebcd & 0x000000F)[2:])
        return datetime.date (_year, _month, _day)
    def Date_Bytes(self):
        return self._read_bytes (self._DATE_OFFSET, self._DATE_SIZE)
    def Size(self):
        return self._read_uint (self._MODULE_SIZE_OFFSET, self._MODULE_SIZE_SIZE)
    def Size_Bytes(self):
        return self._read_bytes (self._MODULE_SIZE_OFFSET, self._MODULE_SIZE_SIZE)
    def Reserved1(self):
        return self._read_uint (self._RESERVED1_OFFSET, self._RESERVED1_SIZE)
    def Reserved1_Bytes(self):
        return self._read_bytes (self._RESERVED1_OFFSET, self._RESERVED1_SIZE)
    def CodeControl(self):
        return self._read_uint (self._CODE_CONTROL_OFFSET, self._CODE_CONTROL_SIZE)
    def CodeControl_Bytes(self):
        return self._read_bytes (self._CODE_CONTROL_OFFSET, self._CODE_CONTROL_SIZE)
    def ErrorEntryPoint(self):
        return self._read_uint (self._ERROR_ENTRY_POINT_OFFSET, self._ERROR_ENTRY_POINT_SIZE)
    def ErrorEntryPoint_Bytes(self):
        return self._read_bytes (self._ERROR_ENTRY_POINT_OFFSET, self._ERROR_ENTRY_POINT_SIZE)
    def GDTLimit(self):
        return self._read_uint (self._GDT_LIMIT_OFFSET, self._GDT_LIMIT_SIZE)
    def GDTLimit_Bytes(self):
        return self._read_bytes (self._GDT_LIMIT_OFFSET, self._GDT_LIMIT_SIZE)
    def GDTBasePtr(self):
        return self._read_uint (self._GDT_BASE_PTR_OFFSET, self._GDT_BASE_PTR_SIZE)
    def GDTBasePtr_Bytes(self):
        return self._read_bytes (self._GDT_BASE_PTR_OFFSET, self._GDT_BASE_PTR_SIZE)
    def SegSel(self):
        return self._read_uint (self._SEGMENT_SELECTOR_OFFSET, self._SEGMENT_SELECTOR_SIZE)
    def SegSel_Bytes(self):
        return self._read_bytes (self._SEGMENT_SELECTOR_OFFSET, self._SEGMENT_SELECTOR_SIZE)
    def EntryPoint(self):
        return self._read_uint (self._ENTRY_POINT_OFFSET, self._ENTRY_POINT_SIZE)
    def EntryPoint_Bytes(self):
        return self._read_bytes (self._ENTRY_POINT_OFFSET, self._ENTRY_POINT_SIZE)
    def Reserved2(self):
        return self._read_bytes (self._RESERVED2_OFFSET, self._RESERVED2_SIZE)
    def KeySize(self):
        return self._read_uint (self._KEY_SIZE_OFFSET, self._KEY_SIZE_SIZE)
    def KeySize_Bytes(self):
        return self._read_bytes (self._KEY_SIZE_OFFSET, self._KEY_SIZE_SIZE)
    def ScratchSize(self):
        return self._read_uint (self._SCRATCH_SIZE_OFFSET, self._SCRATCH_SIZE_SIZE)
    def ScratchSize_Bytes(self):
        return self._read_bytes (self._SCRATCH_SIZE_OFFSET, self._SCRATCH_SIZE_SIZE)
    def RSAPubKey(self):
        return self._read_bytes (self._RSA_PUBKEY_OFFSET,
                                 self.KeySize () * 4)
    def RSAPubExp(self):
        return self._read_uint (self._RSA_PUBEXP_OFFSET, self._RSA_PUBEXP_SIZE)
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
    def _HashObj (self):
        # select hash algorithm for ACM based on SINIT to MLE Data Table version
        if self._sinit_mle_dtv > 6:
            acmhash = hashlib.sha256 ()
        else:
            acmhash = hashlib.sha1 ()
        # We don't hash these fields: RSAPubKey, RSAPubExp, RSASig, Scratch 
        # See section A.1.2 of the Intel MLE Developer's Guide for details.
        acmhash.update (self.ModuleType_Bytes ())
        acmhash.update (self.ModuleSubType_Bytes ())
        acmhash.update (self.HeaderLen_Bytes ())
        acmhash.update (self.HeaderVersion_Bytes ())
        acmhash.update (self.ChipsetID_Bytes ())
        acmhash.update (self.Flags_Bytes ())
        acmhash.update (self.ModuleVendor_Bytes ())
        acmhash.update (self.Date_Bytes ())
        acmhash.update (self.Size_Bytes ())
        acmhash.update (self.Reserved1_Bytes ())
        acmhash.update (self.CodeControl_Bytes ())
        acmhash.update (self.ErrorEntryPoint_Bytes ())
        acmhash.update (self.GDTLimit_Bytes ())
        acmhash.update (self.GDTBasePtr_Bytes ())
        acmhash.update (self.SegSel_Bytes ())
        acmhash.update (self.EntryPoint_Bytes ())
        acmhash.update (self.Reserved2 ())
        acmhash.update (self.KeySize_Bytes ())
        acmhash.update (self.ScratchSize_Bytes ())
        acmhash.update (self.UserArea ())
        return acmhash
    def Digest (self):
        return self._HashObj ().digest ()
    def HexDigest (self):
        return self._HashObj ().hexdigest ()

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
        super (pubConfRegsParse, self).__init__ (pfile, pmmap, poffset=self._offset, psize=self._size)
    # readable config registers
    def Status (self):
        return self._read_uint (self._TXT_STS_OFFSET, self._REG_SIZE)
    def ErrorStatus (self):
        return self._read_uint (self._TXT_ESTS_OFFSET, self._REG_SIZE)
    def ErrorCode (self):
        return self._read_uint (self._TXT_ERRORCODE_OFFSET, self._REG_SIZE)
    def FSBInterface (self):
        return self._read_uint (self._TXT_VER_FSBIF_OFFSET, self._REG_SIZE)
    def DeviceID (self):
        return self._read_uint (self._TXT_DIDVID_OFFSET, self._REG_SIZE)
    def QuickPath (self):
        return self._read_uint (self._TXT_VER_QPIIF_OFFSET, self._REG_SIZE)
    def SINITBase (self):
        return self._read_uint (self._TXT_SINIT_BASE_OFFSET, self._REG_SIZE)
    def SINITSize (self):
        return self._read_uint (self._TXT_SINIT_SIZE_OFFSET, self._REG_SIZE)
    def MLEJoinBase (self):
        return self._read_uint (self._TXT_MLE_JOIN_OFFSET, self._REG_SIZE)
    def HeapBase (self):
        return self._read_uint (self._TXT_HEAP_BASE_OFFSET, self._REG_SIZE)
    def HeapSize (self):
        return self._read_uint (self._TXT_HEAP_SIZE_OFFSET, self._REG_SIZE)
    def DMAProtected (self):
        return self._read_uint (self._TXT_DPR_OFFSET, self._REG_SIZE)
    def PublicKey_Bytes (self):
        _bytes = self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET, 8)
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 8, 8))
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 16, 8))
        _bytes.extend (self._read_bytes (self._TXT_PUBLIC_KEY_OFFSET + 24, 8))
        return _bytes
    def ExtErrorStatus (self):
        return self._read_uint (self._TXT_E2STS_OFFSET, self._REG_SIZE)

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
        return self._read_uint (self._BIOS_DATA_SIZE_OFFSET, self._BIOS_DATA_SIZE_LENGTH)
    def BiosData (self):
        return self._read_bytes (self._BIOS_DATA_OFFSET, self.BiosDataSize () - self._BIOS_DATA_SIZE_LENGTH)
    def OsMleDataSize (self):
        return self._read_uint (self.BiosDataSize (),self._OS_MLE_DATA_SIZE_LENGTH)
    def OsMleData (self):
        return self._read_bytes (self._OsMleDataOffset (), self.OsMleDataSize () - self._OS_MLE_DATA_SIZE_LENGTH)
    def OsSinitDataSize (self):
        return self._read_uint (self.BiosDataSize () + self.OsMleDataSize (), self._OS_SINIT_DATA_SIZE_LENGTH)
    def OsSinitData (self):
        return self._read_bytes (self._OsSinitDataOffset (), self.OsSinitDataSize () - self._OS_SINIT_DATA_SIZE_LENGTH)
    def SinitMleDataSize (self):
        return self._read_uint (self.BiosDataSize () + self.OsMleDataSize () + self.OsSinitDataSize (), self._SINIT_MLE_DATA_SIZE_LENGTH)
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
        return self._read_uint (self._VERSION_OFFSET, self._VERSION_LENGTH)
    def BiosAcmId (self):
        return self._read_bytes (self._BIOS_ACM_ID_OFFSET, self._BIOS_ACM_ID_LENGTH)
    def EdxSenterFlags (self):
        return self._read_uint (self._EDX_SENTER_FLAGS_OFFSET, self._EDX_SENTER_FLAGS_LENGTH)
    def MsegValid (self):
        return self._read_uint (self._MSEG_VALID_OFFSET, self._MSEG_VALID_LENGTH)
    def MsegValid_Bytes (self):
        return self._read_bytes (self._MSEG_VALID_OFFSET, self._MSEG_VALID_LENGTH)
    def SinitHash (self):
        return self._read_bytes (self._SINIT_HASH_OFFSET, self._SINIT_HASH_LENGTH)
    def MleHash (self):
        return self._read_bytes (self._MLE_HASH_OFFSET, self._MLE_HASH_LENGTH)
    def StmHash (self):
        return self._read_bytes (self._STM_HASH_OFFSET, self._STM_HASH_LENGTH)
    def LcpPolicyHash (self):
        return self._read_bytes (self._LCP_POLICY_HASH_OFFSET, self._LCP_POLICY_HASH_LENGTH)
    def PolicyControl (self):
        return self._read_uint (self._POLICY_CONTROL_OFFSET, self._POLICY_CONTROL_LENGTH)
    def PolicyControl_Bytes (self):
        return self._read_bytes (self._POLICY_CONTROL_OFFSET, self._POLICY_CONTROL_LENGTH)
    def RlpWakeupAddr (self):
        return self._read_uint (self._RLP_WAKEUP_ADDR_OFFSET, self._RLP_WAKEUP_ADDR_LENGTH)
    def Reserved (self):
        return self._read_uint (self._RESERVED_OFFSET, self._RESERVED_LENGTH)
    def NumSinitMdrs (self):
        return self._read_uint (self._NUMBER_SINIT_MDRS_OFFSET, self._NUMBER_SINIT_MDRS_LENGTH)
    def SinitMdrTableOffset (self):
        return self._read_uint (self._SINIT_MDR_TABLE_OFFSET_OFFSET, self._SINIT_MDR_TABLE_OFFSET_LENGTH)
    def SinitVtdDmarTableSize (self):
        return self._read_uint (self._SINIT_VTD_DMAR_TABLE_SIZE_OFFSET, self._SINIT_VTD_DMAR_TABLE_SIZE_LENGTH)
    def SinitVtdDmarTableOffset (self):
        return self._read_uint (self._SINIT_VTD_DMAR_TABLE_OFFSET_OFFSET, self._SINIT_VTD_DMAR_TABLE_OFFSET_LENGTH)
    def ProcScrtmStatus (self):
        return self._read_uint (self._PROCESSOR_SCRTM_STATUS_OFFSET, self._PROCESSOR_SCRTM_STATUS_LENGTH)
    def ProcScrtmStatus_Bytes (self):
        return self._read_bytes (self._PROCESSOR_SCRTM_STATUS_OFFSET, self._PROCESSOR_SCRTM_STATUS_LENGTH)

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
        return self._read_uint (self._VERSION_OFFSET, self._VERSION_LENGTH)
    def MlePageTableBase (self):
        return self._read_uint (self._MLE_PAGETABLE_BASE_OFFSET, self._MLE_PAGETABLE_BASE_LENGTH)
    def MleSize (self):
        return self._read_uint (self._MLE_SIZE_OFFSET, self._MLE_SIZE_LENGTH)
    def MleHeaderBase (self):
        return self._read_uint (self._MLE_HEADER_BASE_OFFSET, self._MLE_HEADER_BASE_LENGTH)
    def PmrLowBase (self):
        return self._read_uint (self._PMR_LOW_BASE_OFFSET, self._PMR_LOW_BASE_LENGTH)
    def PmrLowSize (self):
        return self._read_uint (self._PMR_LOW_SIZE_OFFSET, self._PMR_LOW_SIZE_LENGTH)
    def PmrHighBase (self):
        return self._read_uint (self._PMR_HIGH_BASE_OFFSET, self._PMR_HIGH_BASE_LENGTH)
    def PmrHighSize (self):
        return self._read_uint (self._PMR_HIGH_SIZE_OFFSET, self._PMR_HIGH_SIZE_LENGTH)
    def LcpPoBase (self):
        return self._read_uint (self._LCP_PO_BASE_OFFSET, self._LCP_PO_BASE_LENGTH)
    def LcpPoSize (self):
        return self._read_uint (self._LCP_PO_SIZE_OFFSET, self._LCP_PO_SIZE_LENGTH)
    def Capabilities (self):
        return self._read_uint (self._CAPABILITIES_OFFSET, self._CAPABILITIES_LENGTH)
    def Capabilities_Bytes (self):
        return self._read_bytes (self._CAPABILITIES_OFFSET, self._CAPABILITIES_LENGTH)
    def EfiRsdtPointer (self):
        return self._read_uint (self._EFI_RSDT_POINTER_OFFSET, self._EFI_RSDT_POINTER_LENGTH)

class polEntry (binParse):
    _MOD_NUM_OFFSET = 0
    _MOD_NUM_LENGTH = 1
    _PCR_OFFSET = _MOD_NUM_OFFSET + _MOD_NUM_LENGTH
    _PCR_LENGTH = 1
    _HASH_TYPE_OFFSET = _PCR_OFFSET + _PCR_LENGTH
    _HASH_TYPE_LENGTH = 1
    _RESERVED_OFFSET = _HASH_TYPE_OFFSET + _HASH_TYPE_LENGTH
    _RESERVED_LENGTH = 4
    _NUM_HASHES_OFFSET = _RESERVED_OFFSET + _RESERVED_LENGTH
    _NUM_HASHES_LENGTH = 1
    _HASHES_OFFSET = _NUM_HASHES_OFFSET + _NUM_HASHES_LENGTH
    def __init__(self, pbytes):
        super (polEntry, self).__init__ (None, str (pbytes))
    def ModNum (self):
        return self._read_uint (self._MOD_NUM_OFFSET, self._MOD_NUM_LENGTH)
    def Pcr (self):
        return self._read_uint (self._PCR_OFFSET, self. _PCR_LENGTH)
    def HashType (self):
        return self._read_uint (self._HASH_TYPE_OFFSET, self._HASH_TYPE_LENGTH)
    def Reserved (self):
        return self._read_uint (self._RESERVED_OFFSET, self._RESERVED_LENGTH)
    def NumHashes (self):
        return self._read_uint (self._NUM_HASHES_OFFSET, self._NUM_HASHES_LENGTH)
    def Hases (self):
        return 0

class launchCtrlPol (mapParse):
    _VERSION_OFFSET = 0
    _VERSION_LENGTH = 1
    _POLICY_TYPE_OFFSET = _VERSION_OFFSET + _VERSION_LENGTH
    _POLICY_TYPE_LENGTH = 1
    _HASH_ALG_OFFSET = _POLICY_TYPE_OFFSET + _POLICY_TYPE_LENGTH
    _HASH_ALG_LENGTH = 1
    _POLICY_CONTROL_OFFSET = _HASH_ALG_OFFSET + _HASH_ALG_LENGTH
    _POLICY_CONTROL_LENGTH = 4
    _RESERVED_OFFSET = _POLICY_CONTROL_OFFSET + _POLICY_CONTROL_LENGTH
    _RESERVED_LENGTH = 4
    _NUM_ENTRIES_OFFSET = _RESERVED_OFFSET + _RESERVED_LENGTH
    _NUM_ENTRIES_LENGTH = 1
    _ENTRIES_OFFSET = _NUM_ENTRIES_OFFSET + _NUM_ENTRIES_LENGTH
    _TB_POLCTL_EXTEND_PCR17 = 0x1  # extend policy into PCR 17
    _TB_POLCTL_EXTEND_PCR17_OSSINITCAPS = 0x2 # extend OsSinit.Capabilities into PCR 17
    def __init__ (self, pfile, pmmap=False):
        super (launchCtrlPol, self).__init__ (pfile, pmmap)
    def Bytes (self):
        return self._read_bytes (self._VERSION_OFFSET, self._file_size)
    def Version (self):
        return self._read_uint (self._VERSION_OFFSET, self._VERSION_LENGTH)
    def PolicyType (self):
        return self._read_uint (self._POLICY_TYPE_OFFSET, self._POLICY_TYPE_OFFSET)
    def HashAlg (self):
        return self._read_uint (self._HASH_ALG_OFFSET, self._HASH_ALG_LENGTH)
    def PolicyControl (self):
        return self._read_uint (self._POLICY_CONTROL_OFFSET, self._POLICY_CONTROL_LENGTH)
    def PolicyControl_Bytes (self):
        return self._read_bytes (self._POLICY_CONTROL_OFFSET, self._POLICY_CONTROL_LENGTH)
    def Reserved (self):
        return self._read_uint (self._RESERVED_OFFSET, self._RESERVED_LENGTH)
    def NumEntries (self):
        return self._read_uint (self._NUM_ENTRIES_OFFSET, self._NUM_ENTRIES_LENGTH)
    def Entries (self):
        return self._read_bytes (self._ENTRIES_OFFSET, self._file_size - self._ENTRIES_OFFSET)
    def ExtendPCR17_LCP (self):
        if self.PolicyControl () & self._TB_POLCTL_EXTEND_PCR17:
            return True
        else:
            return False
    def ExtendPCR17_OsSinitCaps (self):
        if self.PolicyControl () & self._TB_POLCTL_EXTEND_PCR17_OSSINITCAPS:
            return True
        else:
            return False
        
def pp_bytearray(pbytearray):
    printbuf = list ()
    printbuf.append (str ())
    bytecount = 0
    for byte in pbytearray:
        bytecount += 1
        printbuf[-1] += '{0:0{1}x}'.format (byte, 2)
        if (bytecount % 2) == 0:
            printbuf[-1] += ' '
        if (bytecount % 16) == 0 and bytecount < len (pbytearray):
            printbuf.append (str ())
    return printbuf

def pp_acmFlags (flags):
    print "  Flags raw:      {0}".format (flags.Raw ())
    print "    Production:   {0}".format (flags.Production ())
    print "    Pre Prod:     {0}".format (flags.PreProduction ())
    print "    Prod Sig:     {0}".format (flags.ProductionSigned ())
    print "    Debug Sig:    {0}".format (flags.DebugSigned ())

def pp_ACM (acm):
    print "  ModuleType:     {0}".format (acm.ModuleType ())
    print "  ModuleSubType:  {0}".format (acm.ModuleSubType ())
    print "  HeaderLen:      {0}".format (acm.HeaderLen ())
    print "  HeaderVersion:  {0}".format (acm.HeaderVersion ())
    print "  ChipsetID:      {0}".format (acm.ChipsetID ())
    pp_acmFlags (acm.Flags ())
    print "  ModuleVnedor:   {0}".format (hex (acm.ModuleVendor ()))
    print "  Date:           {0}".format (hex (acm.Date ()))
    print "  DateObj:        {0}".format (acm.DateObj ())
    print "  Size:           {0}".format (acm.Size ())
    print "  Size (bytes):   {0}".format (str (acm.Size () * 4))
    print "  Reserved1:      {0}".format (acm.Reserved1 ())
    print "  CodeControl:    {0}".format (acm.CodeControl ())
    print "  ErrorEntryPoint:{0}".format (acm.ErrorEntryPoint ())
    print "  GDTLimit:       {0}".format (acm.GDTLimit ())
    print "  GDTBasePtr:     {0}".format (acm.GDTBasePtr ())
    print "  SegSel:         {0}".format (acm.SegSel ())
    print "  EntryPoint:     {0}".format (acm.EntryPoint ())
    print "  Reserved2:"
    for _bytestr in pp_bytearray (acm.Reserved2 ()):
        print "    {0}".format (_bytestr)
    print "  KeySize:        {0}".format (acm.KeySize ())
    print "  ScratchSize:    {0}".format (acm.ScratchSize ())
    print "  RSAPubKey:"
    for _bytestr in pp_bytearray (acm.RSAPubKey ()):
        print "    {0}".format (_bytestr)
    print "  RSAPubExp:      {0}".format (acm.RSAPubExp ())
    print "  RSASig:"
    for _bytestr in pp_bytearray (acm.RSASig ()):
        print "    {0}".format (_bytestr)
    print "  Scratch:"
    for _bytestr in pp_bytearray (acm.Scratch ()):
        print "    {0}".format (_bytestr)
    print "  UserArea:"
    for _bytestr in pp_bytearray (acm.UserArea ()):
        print "    {0}".format (_bytestr)

def pp_PubConfRegs (regs):
    print 'TXT Public Config Registers:'
    print '  Status:         {0:#0{1}x}'.format (regs.Status (), regs._REG_SIZE * 2 + 2)
    print '  ErrorStatus:    {0:#0{1}x}'.format (regs.ErrorStatus (), regs._REG_SIZE * 2 + 2)
    print '  ErrorCode:      {0:#0{1}x}'.format (regs.ErrorCode (), regs._REG_SIZE * 2 + 2)
    print '  FSBInterface:   {0:#0{1}x}'.format (regs.FSBInterface (), regs._REG_SIZE * 2 + 2)
    print '  DeviceID:       {0:#0{1}x}'.format (regs.DeviceID (), regs._REG_SIZE * 2 + 2)
    print '  QuickPath:      {0:#0{1}x}'.format (regs.QuickPath (), regs._REG_SIZE * 2 + 2)
    print '  SINITBase:      {0:#0{1}x}'.format (regs.SINITBase (), regs._REG_SIZE * 2 + 2)
    print '  SINITSize:      {0:#0{1}x}'.format (regs.SINITSize (), regs._REG_SIZE * 2 + 2)
    print '  MLEJoinBase:    {0:#0{1}x}'.format (regs.MLEJoinBase (), regs._REG_SIZE * 2 + 2)
    print '  HeapBase:       {0:#0{1}x}'.format (regs.HeapBase (), regs._REG_SIZE * 2 + 2)
    print '  HeapSize:       {0:#0{1}x}'.format (regs.HeapSize (), regs._REG_SIZE * 2 + 2)
    print '  DMAProtected:   {0:#0{1}x}'.format (regs.HeapSize (), regs._REG_SIZE * 2 + 2)
    print '  PublicKey:'
    for _bytestr in pp_bytearray (regs.PublicKey_Bytes ()):
        print "    {0}".format (_bytestr)
    print '  ExtErrorStatus: {0:#0{1}x}'.format (regs.ExtErrorStatus (), regs._REG_SIZE * 2 + 2)

def pp_TxtHeap (heap):
    print 'TXT Heap Data:'
    print '  BiosDataSize:           {0:#0{1}x}'.format (heap.BiosDataSize (), heap._BIOS_DATA_SIZE_LENGTH * 2 + 2)
    print '  OsMleDataSize:          {0:#0{1}x}'.format (heap.OsMleDataSize (), heap._OS_MLE_DATA_SIZE_LENGTH * 2 + 2)
    print '  OsSinitDataSize:        {0:#0{1}x}'.format (heap.OsSinitDataSize (), heap._OS_SINIT_DATA_SIZE_LENGTH * 2 + 2)
    print '  OsMleDataSize:          {0:#0{1}x}'.format (heap.OsMleDataSize (), heap._OS_MLE_DATA_SIZE_LENGTH * 2 + 2)

def pp_SinitToMle (sinitMle):
    print 'SINIT to MLE Data:'
    print '  Version:                 {0:#0{1}x}'.format (sinitMle.Version (), sinitMle._VERSION_LENGTH * 2 + 2)
    print '  BiosAcmId:'
    for _bytestr in pp_bytearray (sinitMle.BiosAcmId ()):
        print '    {0}'.format (_bytestr)
    print '  EdxSenterFlags:          {0:#0{1}x}'.format (sinitMle.EdxSenterFlags (), sinitMle._EDX_SENTER_FLAGS_LENGTH * 2 + 2)
    print '  MsegValid:               {0:#0{1}x}'.format (sinitMle.MsegValid (), sinitMle._MSEG_VALID_LENGTH * 2 + 2)
    print '  SinitHash:'
    for _bytestr in pp_bytearray (sinitMle.SinitHash ()):
        print '    {0}'.format (_bytestr)
    print '  MleHash:'
    for _bytestr in pp_bytearray (sinitMle.MleHash ()):
        print '    {0}'.format (_bytestr)
    print '  StmHash:'
    for _bytestr in pp_bytearray (sinitMle.StmHash ()):
        print '    {0}'.format (_bytestr)
    print '  LcpPolicyHash:'
    for _bytestr in pp_bytearray (sinitMle.LcpPolicyHash ()):
        print '    {0}'.format (_bytestr)
    print '  PolicyControl:           {0:#0{1}x}'.format (sinitMle.PolicyControl (), sinitMle._POLICY_CONTROL_LENGTH * 2 + 2)
    print '  RlpWakeupAddr:           {0:#0{1}x}'.format (sinitMle.RlpWakeupAddr (), sinitMle._RLP_WAKEUP_ADDR_LENGTH * 2 + 2)
    print '  Reserved:                {0:#0{1}x}'.format (sinitMle.Reserved (), sinitMle._RESERVED_LENGTH * 2 + 2)
    print '  NumSinitMdrs:            {0:#0{1}x}'.format (sinitMle.NumSinitMdrs (), sinitMle._NUMBER_SINIT_MDRS_LENGTH * 2 + 2)
    print '  SinitMdrTableOffset:     {0:#0{1}x}'.format (sinitMle.SinitMdrTableOffset (), sinitMle._SINIT_MDR_TABLE_OFFSET_LENGTH * 2 + 2)
    print '  SinitVtdDmarTableSize:   {0:#0{1}x}'.format (sinitMle.SinitVtdDmarTableSize (), sinitMle._SINIT_VTD_DMAR_TABLE_SIZE_LENGTH * 2 + 2)
    print '  SinitVtdDmarTableOffset: {0:#0{1}x}'.format (sinitMle.SinitVtdDmarTableOffset (), sinitMle._SINIT_VTD_DMAR_TABLE_OFFSET_LENGTH * 2 + 2)
    print '  ProcScrtmStatus:         {0:#0{1}x}'.format (sinitMle.ProcScrtmStatus (), sinitMle._PROCESSOR_SCRTM_STATUS_LENGTH * 2 + 2)

def pp_OsToSinit (os_sinit):
    print 'OsToSinit:'
    print '  Version:          {0:#0{1}x}'.format (os_sinit.Version (), os_sinit._VERSION_LENGTH * 2 + 2)
    print '  MlePageTableBase: {0:#0{1}x}'.format (os_sinit.MlePageTableBase (), os_sinit._MLE_PAGETABLE_BASE_LENGTH + 2)
    print '  MleSize:          {0:#0{1}x}'.format (os_sinit.MleSize (), os_sinit._MLE_SIZE_LENGTH * 2 + 2)
    print '  MleHeaderBase:    {0:#0{1}x}'.format (os_sinit.MleHeaderBase (), os_sinit._MLE_HEADER_BASE_LENGTH * 2 + 2)
    print '  PmrLowBase:       {0:#0{1}x}'.format (os_sinit.PmrLowBase (), os_sinit._PMR_LOW_BASE_LENGTH * 2 + 2)
    print '  PmrLowSize:       {0:#0{1}x}'.format (os_sinit.PmrLowSize (), os_sinit._PMR_LOW_SIZE_LENGTH * 2 + 2)
    print '  PmrHighBase:      {0:#0{1}x}'.format (os_sinit.PmrHighBase (), os_sinit._PMR_HIGH_BASE_LENGTH * 2 + 2)
    print '  PmrHighSize:      {0:#0{1}x}'.format (os_sinit.PmrHighSize (), os_sinit._PMR_HIGH_SIZE_LENGTH * 2 + 2)
    print '  LcpPoBase:        {0:#0{1}x}'.format (os_sinit.LcpPoBase (), os_sinit._LCP_PO_BASE_LENGTH * 2 + 2)
    print '  LcpPoSize:        {0:#0{1}x}'.format (os_sinit.LcpPoSize (), os_sinit._LCP_PO_SIZE_LENGTH * 2 + 2)
    print '  Capabilities:     {0:#0{1}x}'.format (os_sinit.Capabilities (), os_sinit._CAPABILITIES_LENGTH * 2 + 2)
    print '  EfiRsdtPointer:   {0:#0{1}x}'.format (os_sinit.EfiRsdtPointer (), os_sinit._EFI_RSDT_POINTER_LENGTH * 2 + 2)

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

class mleHeader (binParse):
    _UUID_OFFSET = 0
    _UUID_SIZE = 16
    _LENGTH_OFFSET = _UUID_OFFSET + _UUID_SIZE
    _LENGTH_SIZE = 4
    _VERSION_OFFSET = _LENGTH_OFFSET + _LENGTH_SIZE
    _VERSION_SIZE = 4

    def __init__(self, pfile, pmmap=False, poffset=0):
        self._offset = poffset
        super (mleHeader, self).__init__ (pfile, pfile)
    def uuid_bytes (self):
        return self._read_bytes (self._offset + self._UUID_OFFSET, self._UUID_SIZE)
    def uuid (self):
        return uuid.UUID (bytes=str (self.uuid_bytes ()))
    def length (self):
        return self._read_uint (self._offset + self._LENGTH_OFFSET, self._LENGTH_SIZE)
    def version (self):
        return self._read_uint (self._offset + self._VERSION_OFFSET, self._VERSION_SIZE)
    def entry_point (self):
        raise NotImplementedError ('mleHeader.version not implemented')
    def first_valid_page (self):
        raise NotImplementedError ('mleHeader.first_valid_page not implemented')
    def mle_start_off (self):
        raise NotImplementedError ('mleHeader.mle_start_off not implemented')
    def mle_end_off (self):
        raise NotImplementedError ('mleHeader.mle_end_off not implemented')
    def capabilities (self):
        raise NotImplementedError ('mleHeader.capabilities not implemented')
    def cmdline_start_off (self):
        raise NotImplementedError ('mleHeader.cmdline_start_off not implemented')
    def cmdline_end_off (self):
        raise NotImplementedError ('mleHeader.cmdline_end_off not implemented')

def hash_module (cmdline, fd_module):
    '''  from tboot-1.7.3/tboot/common/policy.c
    cmdline is first stripped of leading spaces, file name, then
    any spaces until the next non-space char
    (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "") '''
    try:
        cmdline = cmdline.strip ().rstrip ()
        cmdline = cmdline [cmdline.index (' '):].strip ()
    except ValueError:
        cmdline = ''

    ''' from tboot-1.7.3/tboot/common/policy.c
    final hash is SHA-1( SHA-1(cmdline) | SHA-1(image) ) '''
    cmd_hash = hashlib.sha1 ()
    mod_hash = hashlib.sha1 ()
    both_hash = hashlib.sha1 ()
    cmd_hash.update (cmdline)
    ''' assume module is small enough to cache, may need to hash in chunks
    to accomodate larger modules'''
    mod_hash.update (fd_module.read ())
    both_hash.update (cmd_hash.digest ())
    both_hash.update (mod_hash.digest ())
    return both_hash
