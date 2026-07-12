BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG   ?= clang
MAPDIR  := /sys/fs/bpf/$(PROG)/maps
MAPFILE := $(MAPDIR)/enabled

.PHONY: all clean load unload enable disable status test

all:	$(PROG).bpf.o

../vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).bpf.o: $(PROG).bpf.c ../vmlinux.h ../common.bpf.h
	$(CLANG) -target bpf \
		-Wall -Wextra -Wno-missing-declarations -Wno-unused-parameter \
		-O2 -g -o $@ -c $< -I..
	llvm-strip -g $@

clean:
	$(RM) $(PROG).bpf.o

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
		echo "$(PROG): loaded, enabled"; \
	else \
		echo "$(PROG): loaded, disabled"; \
	fi

test:
	@if sudo test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		$(SUDO) env LOADED=1 bats ../tests/$(PROG).bats; \
	else \
		$(SUDO) bats ../tests/$(PROG).bats; \
	fi
