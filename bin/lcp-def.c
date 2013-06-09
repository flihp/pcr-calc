#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

#define TB_HALG_SHA1    0

#ifndef SHA1_LENGTH
#define SHA1_LENGTH        20
#endif
#ifndef SHA256_LENGTH
#define SHA256_LENGTH      32
#endif

/*
 * policy types
 */
enum {
    TB_POLTYPE_CONT_NON_FATAL,     /* ignore all non-fatal errors and */
                                   /* continue */
    TB_POLTYPE_CONT_VERIFY_FAIL,   /* ignore verification errors and */
                                   /* halt otherwise */
    TB_POLTYPE_HALT,               /* halt on any errors */
    TB_POLTYPE_MAX
};

/*
 * policy hash types
 */
enum {
    TB_HTYPE_ANY,
    TB_HTYPE_IMAGE,
};

#define TB_POL_MAX_MOD_NUM     127    /* largest supported module number */
#define TB_POL_MOD_NUM_ANY     129    /* matches any module number */
                                      /* (should be last entry) */

#define TB_POL_MAX_PCR         23     /* largest supported PCR number */
#define TB_POL_PCR_NONE        255    /* don't extend measurement into a PCR */

typedef uint8_t sha1_hash_t[SHA1_LENGTH];

typedef union {
    uint8_t    sha1[SHA1_LENGTH];
    uint8_t    sha256[SHA256_LENGTH];
} tb_hash_t;

typedef struct __packed {
    uint8_t      mod_num;         /* 0-based or TB_POL_MOD_NUM_* */
    uint8_t      pcr;             /* PCR number (0-23) or TB_POL_PCR_* */
    uint8_t      hash_type;       /* TB_HTYPE_* */
    uint32_t     reserved;
    uint8_t      num_hashes;
    tb_hash_t    hashes[];
} tb_policy_entry_t;

#define TB_POLCTL_EXTEND_PCR17       0x1  /* extend policy into PCR 17 */

typedef struct __packed {
    uint8_t             version;          /* currently 2 */
    uint8_t             policy_type;      /* TB_POLTYPE_* */
    uint8_t             hash_alg;         /* TB_HALG_* */
    uint32_t            policy_control;   /* bitwise OR of TB_POLCTL_* */
    uint32_t            reserved;
    uint8_t             num_entries;
    tb_policy_entry_t   entries[];
} tb_policy_t;

static inline unsigned int get_hash_size(uint8_t hash_alg)
{
    return (hash_alg == TB_HALG_SHA1) ? SHA1_LENGTH : 0;
}

static inline size_t calc_policy_entry_size(const tb_policy_entry_t *pol_entry,
                                            uint8_t hash_alg)
{
    if ( pol_entry == NULL )
        return 0;

    size_t size = sizeof(*pol_entry);
    /* tb_policy_entry_t has empty hash array, which isn't counted in size */
    /* so add size of each hash */
    size += pol_entry->num_hashes * get_hash_size(hash_alg);

    return size;
}

static inline size_t calc_policy_size(const tb_policy_t *policy)
{
    size_t size = sizeof(*policy);
    int i = 0;

    /* tb_policy_t has empty array, which isn't counted in size */
    /* so add size of each policy */
    const tb_policy_entry_t *pol_entry = policy->entries;
    for ( i = 0; i < policy->num_entries; i++ ) {
        size_t entry_size = calc_policy_entry_size(pol_entry,
                                                   policy->hash_alg);
        pol_entry = (void *)pol_entry + entry_size;
        size += entry_size;
    }

    return size;
}

/* default policy */
static const tb_policy_t _def_policy = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 2,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        }
    }
};

/* default policy for Details/Authorities pcr mapping */
static const tb_policy_t _def_policy_da = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 2,
    entries        : {
        {   /* mod 0 is extended to PCR 17 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 17 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 17,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        }
    }
};

/* default policy from XT 3.1.2 */
static const tb_policy_t _xt_policy = {
    version        : 2,
    policy_type    : TB_POLTYPE_HALT,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 2,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        }
    }
};

static int da_flag = 0;
static int help_flag = 0;

static const char *short_option = "dh";
static struct option long_options[] =
{
    /* These options set a flag. */
    {"da", no_argument, &da_flag, 1},
    {"help", no_argument, &help_flag, 1},
    {0, 0, 0, 0}
};

static int
parse_cmdline(int argc, char * argv[])
{
    int c;
/* getopt_long stores the option index here. */
    int option_index = 0;
    
    while ((c = getopt_long (argc, argv, short_option, long_options,
                             &option_index)) != -1) {
        switch (c){
        case 0:
            break;
        case 'd':
            da_flag = 1;
            break;
        case 'h':
            help_flag = 1;
            break;
        default:
            return -1;
        }
    }
    return 0;
}

int
main (int argc, char* argv[]) {
    int pol_size = 0, num = 0;
    const tb_policy_t* policy = NULL;

    if (parse_cmdline(argc, argv) == -1) {
        exit (1);
    }

    if (help_flag) {
        fprintf (stderr, "Usage: %s [--da]\n", argv[0]);
        exit (0);
    }

    policy = da_flag ? &_def_policy_da : &_def_policy;

    pol_size = calc_policy_size (policy);
    fprintf (stderr, "pol_size: %d\n", pol_size);
    do {
        num += write (STDOUT_FILENO, policy + num, pol_size - num);
    } while (num < pol_size);

    fprintf (stderr, "wrote: %d\n", num);
    exit (0);
}
