ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/;s/s390x/s390/;s/ppc64le/powerpc/')
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG   ?= clang
CFLAGS  := -g -O2 -Wall -Wextra -Wno-missing-declarations
MAPDIR  := /sys/fs/bpf/$(PROG)/maps
MAPFILE := $(MAPDIR)/enabled

.PHONY: all clean load unload enable disable status test

all:	$(PROG).bpf.o

vmlinux.h:
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).bpf.o: $(PROG).bpf.c vmlinux.h ../common.bpf.h
	$(CLANG) $(CFLAGS) -Wno-unused-parameter -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I.. -c $< -o $@

clean:
	$(RM) $(PROG).bpf.o vmlinux.h

unload load enable disable status: SUDO := sudo

load: $(PROG).bpf.o
	$(SUDO) $(BPFTOOL) prog loadall $< /sys/fs/bpf/$(PROG) pinmaps $(MAPDIR) autoattach

unload:
	@$(SUDO) $(RM) -r -v /sys/fs/bpf/$(PROG)

enable:
	$(SUDO) bpftool map update pinned $(MAPFILE) key 0 0 0 0 value 01

disable:
	$(SUDO) bpftool map update pinned $(MAPFILE) key 0 0 0 0 value 00

status:
	@if ! $(SUDO) test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		echo "not loaded"; \
	elif $(SUDO) bpftool -j map dump pinned $(MAPFILE) 2>/dev/null | jq -e '.[0].value[0] != "0x00"' >/dev/null; then \
		echo "loaded, enabled"; \
	else \
		echo "loaded, disabled"; \
	fi

test:
	@if sudo test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		$(SUDO) env LOADED=1 bats ../tests/$(PROG).bats; \
	else \
		$(SUDO) bats ../tests/$(PROG).bats; \
	fi
