BPFTOOL   ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG     ?= clang
BPFTARGET ?= bpfel
MAPDIR    := /sys/fs/bpf/$(PROG)/maps
MAPFILE   := $(MAPDIR)/enabled
LOGFILE   := $(MAPDIR)/logging
OBJ       := $(PROG).$(BPFTARGET).o

.PHONY: all clean load unload enable disable status log-enable log-disable test

all:	$(OBJ)

../vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).$(BPFTARGET).o: $(PROG).bpf.c ../vmlinux.h ../common.bpf.h
	$(CLANG) -target $(BPFTARGET) \
		-Wall -Wextra -Wno-missing-declarations -Wno-unused-parameter \
		-O2 -g -o $@ -c $< -I..
	llvm-strip -g $@

clean:
	$(RM) $(PROG).*.o

unload load enable disable status log-enable log-disable: SUDO := sudo

load: $(OBJ)
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
		exit 0; \
	fi; \
	if $(SUDO) bpftool -j map dump pinned $(MAPFILE) 2>/dev/null | jq -e '.[0].value[0] != "0x00"' >/dev/null; then \
		enabled=enabled; \
	else \
		enabled=disabled; \
	fi; \
	if $(SUDO) bpftool -j map dump pinned $(LOGFILE) 2>/dev/null | jq -e '.[0].value[0] != "0x00"' >/dev/null; then \
		logging=logging; \
	else \
		logging=not-logging; \
	fi; \
	echo "$(PROG): loaded, $$enabled, $$logging"

log-enable:
	$(SUDO) bpftool map update pinned $(LOGFILE) key 0 0 0 0 value 01

log-disable:
	$(SUDO) bpftool map update pinned $(LOGFILE) key 0 0 0 0 value 00

test:
	@if sudo test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		$(SUDO) env LOADED=1 bats ../tests/$(PROG).bats; \
	else \
		$(SUDO) bats ../tests/$(PROG).bats; \
	fi
