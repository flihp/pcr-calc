bin_PROGRAMS = lcp-def
bin_SCRIPTS = acm-dump \
              lcp-dump \
              module-hash \
              pcr17 \
              pcr18 \
              pcr19 \
              pcremu \
              sinithash \
              txtheap-dump
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = acm-dump.in \
             lcp-dump.in \
             module-hash.in \
             pcr17.in \
             pcr18.in \
             pcr19.in \
             pcremu.in \
             sinithash.in \
             txtheap-dump.in
SUFFIXES = .in

do_subst = sed -e 's,[@]pythondir[@],$(pythondir),g' \
               -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
               -e 's,[@]VERSION[@],$(VERSION),g'

acm-dump: acm-dump.in Makefile
lcp-dump: lcp-dump.in Makefile
pcr17: pcr17.in Makefile
pcr18: pcr18.in Makefile
pcr19: pcr19.in Makefile
pcremu: pcremu.in Makefile
sinithash: sinithash.in Makefile
txtheap-dump: txtheap-dump.in Makefile

.in:
	$(do_subst) < $< > $@
	chmod +x $@
