#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

VERSION=`dpkg-parsechangelog -lChangelog | grep ^Version: | cut -f2 -d\ `

../msva-perl_$(VERSION).orig.tar.gz: msva-perl msva.protocol.README COPYING
	git archive --format tar -o $@ --prefix=msva-perl-$(VERSION)/ $<

tarball: ../msva-perl_$(VERSION).orig.tar.gz

debian-package: tarball
	git buildpackage -uc -us

.PHONY: tarball debian-package
