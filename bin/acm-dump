#!/usr/bin/python
#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#

import txt
import pcrutil

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
    acm = txt.acmParse (f)
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
    for _bytestr in pcrutil.prettyprint_bytearray (acm.Reserved2 ()):
        print "    {0}".format (_bytestr)
    print "  KeySize:        {0}".format (acm.KeySize ())
    print "  ScratchSize:    {0}".format (acm.ScratchSize ())
    print "  RSAPubKey:"
    for _bytestr in pcrutil.prettyprint_bytearray (acm.RSAPubKey ()):
        print "    {0}".format (_bytestr)
    print "  RSAPubExp:      {0}".format (acm.RSAPubExp ())
    print "  RSASig:"
    for _bytestr in pcrutil.prettyprint_bytearray (acm.RSASig ()):
        print "    {0}".format (_bytestr)
    print "  Scratch:"
    for _bytestr in pcrutil.prettyprint_bytearray (acm.Scratch ()):
        print "    {0}".format (_bytestr)
    print "  UserArea:"
    for _bytestr in pcrutil.prettyprint_bytearray (acm.UserArea ()):
        print "    {0}".format (_bytestr)
    sys.exit (0)

if __name__ == "__main__":
    main()
