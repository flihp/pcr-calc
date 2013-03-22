bin_SCRIPTS = acm-dump lcp-dump pcr17 txtheap-dump
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = acm-dump.in lcp-dump.in pcr17.in txtheap-dump.in
SUFFIXES = .in

do_subst = sed -e 's,[@]pythondir[@],$(pythondir),g' \
               -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
               -e 's,[@]VERSION[@],$(VERSION),g'

acm-dump: acm-dump.in Makefile
lcp-dump: lcp-dump.in Makefile
pcr17: pcr17.in Makefile
txtheap-dump: txtheap-dump.in Makefile

.in:
	$(do_subst) < $< > $@
	chmod +x $@
