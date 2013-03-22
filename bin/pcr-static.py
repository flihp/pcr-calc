#!/usr/bin/env python
#
# Copyright 2013 Philip Tricca <flihp@twobit.us>
#

import base64
import hashlib
import sys

# /* default policy */
# static const tb_policy_t _def_policy = {
#     version        : 2,
#     policy_type    : TB_POLTYPE_CONT_NON_FATAL,
#     policy_control : TB_POLCTL_EXTEND_PCR17,
#     num_entries    : 2,
#     entries        : {
#         {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
#             mod_num    : 0,
#             pcr        : TB_POL_PCR_NONE,
#             hash_type  : TB_HTYPE_ANY,
#             num_hashes : 0
#         },
#         {   /* all other modules are extended to PCR 19 */
#             mod_num    : TB_POL_MOD_NUM_ANY,
#             pcr        : 19,
#             hash_type  : TB_HTYPE_ANY,
#             num_hashes : 0
#         }
#     }
# };

# /* default policy for Details/Authorities pcr mapping */
# static const tb_policy_t _def_policy_da = {
#     version        : 2,
#     policy_type    : TB_POLTYPE_CONT_NON_FATAL,
#     policy_control : TB_POLCTL_EXTEND_PCR17,
#     num_entries    : 2,
#     entries        : {
#         {   /* mod 0 is extended to PCR 17 by default, so don't re-extend it */
#             mod_num    : 0,
#             pcr        : TB_POL_PCR_NONE,
#             hash_type  : TB_HTYPE_ANY,
#             num_hashes : 0
#         },
#         {   /* all other modules are extended to PCR 17 */
#             mod_num    : TB_POL_MOD_NUM_ANY,
#             pcr        : 17,
#             hash_type  : TB_HTYPE_ANY,
#             num_hashes : 0
#         }
#     }
# };

def main ():

    # the proverbial "first extend"
    bytes4zero  = base64.b16decode ('00000000')
    bytes8zero  = base64.b16decode ('0000000000000000')
    bytes20zero = base64.b16decode ('0000000000000000000000000000000000000000')
    first_hash = hashlib.sha1 ()
    acm_sha256 = base64.b16decode('30ed7bc9e1f32a7e489fbd15d85185f4ffd88834a3104d19334391783d55ebbf', True)
    print 'acm_hash:\n  {0}'.format (acm_sha256.encode ('hex'))

    first_hash.update (acm_sha256)
    first_hash.update (bytes4zero)
    print 'sha1 (sha256 (acm) | edx):\n  {0}'.format (first_hash.hexdigest ())

    second_hash = hashlib.sha1 ()
    second_hash.update (bytes20zero)
    second_hash.update (first_hash.digest ())
    print 'extend1 = sha1 (pcr[17] | sha1 (sha256 (acm) | edx)):\n  {0}'.format (second_hash.hexdigest ())
    # end first extend

    bios_acm = base64.b16decode ('80000000201010220000b001ffffffffffffffff', True)
    mseg_valid = bytes8zero
    stm_hash = bytes20zero
    pol_control = bytes4zero
    lcp_hash = bytes20zero
    os_sinit_caps = bytes4zero
    scrtm_status = bytes4zero

    print 'bios_acm:      {0}'.format (bios_acm.encode ('hex'))
    print 'mseg_valid:    {0}'.format (mseg_valid.encode ('hex'))
    print 'stm_hash:      {0}'.format (stm_hash.encode ('hex'))
    print 'pol_control:   {0}'.format (pol_control.encode ('hex'))
    print 'lpc_hash:      {0}'.format (lcp_hash.encode ('hex'))
    print 'os_sinit_caps: {0}'.format (os_sinit_caps.encode ('hex'))
    print 'scrtm_status:  {0}'.format (scrtm_status.encode ('hex'))

    # sha1 (bios_acm | mseg_valid | stm_hash | pol_control | lcp_hash | os_sinit_caps | scrtm_status)
    third_hash = hashlib.sha1 ()
    third_hash.update (bios_acm)
    third_hash.update (mseg_valid)
    third_hash.update (stm_hash)
    third_hash.update (pol_control)
    third_hash.update (lcp_hash)
    third_hash.update (os_sinit_caps)
    third_hash.update (scrtm_status)
    print 'dat_sha1 = sha1 (bios_acm | mseg_valid | stm_hash | pol_control | lcp_hash | os_sinit_caps | scrtm_status):\n  {0}'.format (third_hash.hexdigest ())

    # sha1 (pcr[17] | that last stuff)
    fourth_hash = hashlib.sha1 ()
    fourth_hash.update (second_hash.digest ())
    fourth_hash.update (third_hash.digest ())
    print 'extend2 = sha1 (extend1 | dat_sha1):\n  {0}'.format (fourth_hash.hexdigest ())

    # LCP & Policy Control hash
    policy_control = base64.b16decode ('01000000', True)
    pol_hash = base64.b16decode ('ab41624e7d71f068d48e1c2f43e616bf40671c39', True)
    vl_hash = hashlib.sha1 ()
    vl_hash.update (policy_control)
    vl_hash.update (pol_hash)
    print 'lcp_sha1 = sha1 (policy_control | LCP hash)\n  {0}'.format (vl_hash.hexdigest ())

    fifth_hash = hashlib.sha1 ()
    fifth_hash.update (fourth_hash.digest ())
    fifth_hash.update (vl_hash.digest ())
    print 'pcr_final = sha1 (extend2 | lcp_sha1)):\n  {0}'.format (fifth_hash.hexdigest ())

if __name__ == "__main__":
    main()
