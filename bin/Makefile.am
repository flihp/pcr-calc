bin_SCRIPTS = acm-dump
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = acm-dump.in

do_subst = sed -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
               -e 's,[@]VERSION[@],$(VERSION),g'

acm-dump: acm-dump.in Makefile
	$(do_subst) < $< > $@
	chmod +x $@
