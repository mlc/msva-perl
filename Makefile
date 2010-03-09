#!/usr/bin/make -f

# Makefile for xul-ext-monkeysphere

# © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

VERSION=`dpkg-parsechangelog -lChangelog | grep ^Version: | cut -f2 -d\ `
DEBIAN_VERSION=`dpkg-parsechangelog | grep ^Version: | cut -f2 -d\ `

all: msva-perl.1

msva-perl.1: msva-perl
	pod2man msva-perl msva-perl.1

release: tarball
	git tag -s msva-perl/$(VERSION) -m "releasing msva-perl version $(VERSION)"

tarball: msva-perl msva.protocol.README COPYING Makefile
	git archive --format tar --prefix=msva-perl-$(VERSION)/ HEAD | gzip -n -9 > ../msva-perl-$(VERSION).tar.gz

clean: 
	rm -f msva-perl.1

debian-package:
	debuild -uc -us -i'^\.git|notes_from_whiteboard\.txt'

debian-tag:
	git tag -s debian/$(DEBIAN_VERSION) -m "tagging msva-perl debian packaging version $(DEBIAN_VERSION)"

.PHONY: release tarball debian-package debian-tag all clean
