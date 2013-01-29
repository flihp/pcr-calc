#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#
# miscellaneous utility functions used in or related to pcr-calc

# takes a bytearray parameter
# returns a list of strings as you would see in a hex editor
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
