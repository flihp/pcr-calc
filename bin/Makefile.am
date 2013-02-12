bin_SCRIPTS = acm-dump pcr17
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = acm-dump.in pcr17.in
SUFFIXES = .in

do_subst = sed -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
               -e 's,[@]VERSION[@],$(VERSION),g'

acm-dump: acm-dump.in Makefile
pcr17: pcr17.in Makefile

.in:
	$(do_subst) < $< > $@
	chmod +x $@
