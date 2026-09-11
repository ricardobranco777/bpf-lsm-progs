PROGS := fs_mount_restrict \
	 setuid_restrict \
	 socket_create_restrict \
	 userns_restrict

TARGET    ?= /opt/bpf-lsm-progs
# Detect endianness
DEFAULT_BPFTARGET := $(shell [ "$$(printf '\1\2\3\4' | od -An -tx4 | tr -d ' ')" = "01020304" ] && echo bpfeb || echo bpfel)
BPFTARGET ?= $(DEFAULT_BPFTARGET)
BPFTOOL   ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
SUDO      ?= sudo

SPEC      := packaging/rpm/bpf-lsm-progs.spec
RPM_TOPDIR:= $(CURDIR)/packaging/rpm/build
VERSION   := $(shell awk '/^Version:/{print $$2}' $(SPEC))

TARGETS	= load unload test
.PHONY: all clean install uninstall $(TARGETS) $(PROGS) rpm deb

all:	$(PROGS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROGS): vmlinux.h
	@$(MAKE) --no-print-directory -C $@

clean:
	@for dir in $(PROGS); do \
		$(MAKE) --no-print-directory -C $$dir $@; \
	done
	$(RM) vmlinux.h
	$(RM) -r dist packaging/rpm/build

$(TARGETS):
	@for dir in $(PROGS); do \
		$(MAKE) --no-print-directory -C $$dir $@; \
	done

install: all
	@for p in $(PROGS); do \
		$(SUDO) install -D -m 644 "$$p/$$p.$(BPFTARGET).o" "$(TARGET)/$$p/$$p.$(BPFTARGET).o"; \
	done
	$(SUDO) $(MAKE) --no-print-directory -C initramfs install TARGET=$(TARGET) BPFTARGET=$(BPFTARGET)

uninstall:
	$(SUDO) rm -rf $(TARGET)
	$(SUDO) $(MAKE) --no-print-directory -C initramfs uninstall

rpm:
	mkdir -p $(RPM_TOPDIR)/SOURCES
	git archive --prefix=bpf-lsm-progs-$(VERSION)/ \
		-o $(RPM_TOPDIR)/SOURCES/bpf-lsm-progs-$(VERSION).tar.gz HEAD
	rpmbuild --define "_topdir $(RPM_TOPDIR)" -bb $(SPEC)
	mkdir -p dist
	cp $(RPM_TOPDIR)/RPMS/*/*.rpm dist/

deb:
	rm -rf debian
	cp -a packaging/debian debian
	dpkg-buildpackage -us -uc -b
	rm -rf debian
	mkdir -p dist
	mv ../bpf-lsm-progs_*.deb dist/
