#!/usr/bin/python
#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#

import datetime
import struct

# takes a bytearray parameter
# returns a list of formatted strings like you would expect
#   from a hex editor
def prettyprint_bytearray(pbytearray):
    printbuf = list ()
    printbuf.append (str ())
    bytecount = 0
    for byte in pbytearray:
        bytecount += 1
        printbuf[-1] += hex (byte)[2]
        if (bytecount % 4) == 0:
            printbuf[-1] += ' '
        if (bytecount % 32) == 0 and bytecount < len (pbytearray):
            printbuf.append (str ())
    return printbuf

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
        _year = int (hex ((self._datebcd & 0xFFFF0000) >> 16)[2:])
        _month = int (hex ((self._datebcd & 0x0000FF00) >> 8)[2:])
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

def main():
    import sys
    import os

    usage = "Usage: {0} [acm file]".format(sys.argv[0])

    if len(sys.argv) != 2:
        print usage
        sys.exit (1)

    if not os.path.isfile (sys.argv [1]):
        print usage
        sys.exit (1)

    f = open (sys.argv [1])
    acm = acmParse (f)
    print "  ModuleType:     {0}".format (acm.ModuleType ())
    print "  ModuleSubType:  {0}".format (acm.ModuleSubType ())
    print "  HeaderLen:      {0}".format (acm.HeaderLen ())
    print "  HeaderVersion:  {0}".format (acm.HeaderVersion ())
    print "  ChipsetID:      {0}".format (acm.ChipsetID ())
    flags = acm.Flags ()
    print "  Flags raw:      {0}".format (flags.Raw ())
    print "    Production:   {0}".format (flags.Production ())
    print "    Pre Prod:     {0}".format (flags.PreProduction ())
    print "    Prod Sig:     {0}".format (flags.ProductionSigned ())
    print "    Debug Sig:    {0}".format (flags.DebugSigned ())
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
    for _bytestr in prettyprint_bytearray (acm.Reserved2 ()):
        print "    {0}".format (_bytestr)
    print "  KeySize:        {0}".format (acm.KeySize ())
    print "  ScratchSize:    {0}".format (acm.ScratchSize ())
    print "  RSAPubKey:"
    for _bytestr in prettyprint_bytearray (acm.RSAPubKey ()):
        print "    {0}".format (_bytestr)
    print "  RSAPubExp:      {0}".format (acm.RSAPubExp ())
    print "  RSASig:"
    for _bytestr in prettyprint_bytearray (acm.RSASig ()):
        print "    {0}".format (_bytestr)
    print "  Scratch:"
    for _bytestr in prettyprint_bytearray (acm.Scratch ()):
        print "    {0}".format (_bytestr)
    print "  UserArea:"
    for _bytestr in prettyprint_bytearray (acm.UserArea ()):
        print "    {0}".format (_bytestr)
    sys.exit (0)

if __name__ == "__main__":
    main()
