#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

VERSION=`dpkg-parsechangelog -lChangelog | grep ^Version: | cut -f2 -d\ `

all: msva-perl.1

msva-perl.1: msva-perl
	pod2man msva-perl msva-perl.1

release: msva-perl msva.protocol.README COPYING Makefile
	git archive --format tar --prefix=msva-perl-$(VERSION)/ HEAD | gzip -n -9 > ../msva-perl-$(VERSION).tar.gz

clean: 
	rm -f msva-perl.1

.PHONY: release all clean
