#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

VERSION=`dpkg-parsechangelog -lChangelog | grep ^Version: | cut -f2 -d\ `
DEBIAN_VERSION=`dpkg-parsechangelog | grep ^Version: | cut -f2 -d\ `

all: msva-perl.1

msva-perl.1: msva-perl
	pod2man msva-perl msva-perl.1

clean: 
	rm -f msva-perl.1

debian-package:
	git buildpackage -uc -us

upstream-tag:
	git tag -s msva-perl/$(VERSION) -m "releasing msva-perl version $(VERSION)"
debian-tag:
	git tag -s msva-perl_debian/$(DEBIAN_VERSION) -m "tagging msva-perl debian packaging version $(DEBIAN_VERSION)"

.PHONY: upstream-tag debian-package debian-tag all clean
