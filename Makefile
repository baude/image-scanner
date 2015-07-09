SHELL = /bin/sh


DESTDIR="/"

install:
	python setup.py build
	python setup.py install --root=$(DESTDIR)
	mkdir -p $(DESTDIR)/etc/image-scanner
	cp conf/image-scanner.conf $(DESTDIR)/etc/image-scanner
	cp conf/image-scanner-client.conf $(DESTDIR)/etc/image-scanner
	install -d $(DESTDIR)/usr/share/man/man1
	install -m 644 docs/*.1 $(DESTDIR)/usr/share/man/man1

clean:
	rm -fvr packaging/image-scanner-*
	rm -fvr packaging/noarch
