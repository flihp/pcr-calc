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
        printbuf[-1] += '{0:0{1}x}'.format (byte, 2)
        if (bytecount % 2) == 0:
            printbuf[-1] += ' '
        if (bytecount % 16) == 0 and bytecount < len (pbytearray):
            printbuf.append (str ())
    return printbuf
