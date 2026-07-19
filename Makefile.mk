BPFTOOL   ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG     ?= clang
# Detect endianness
DEFAULT_BPFTARGET := $(shell [ "$$(printf '\1\2\3\4' | od -An -tx4 | tr -d ' ')" = "01020304" ] && echo bpfeb || echo bpfel)
BPFTARGET ?= $(DEFAULT_BPFTARGET)
LOGGING   ?= 1
OBJ       := $(PROG).$(BPFTARGET).o
SUDO      := sudo

.PHONY: all clean load unload test

all:	$(OBJ)

../vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).$(BPFTARGET).o: $(PROG).bpf.c ../vmlinux.h ../common.bpf.h
	$(CLANG) -target $(BPFTARGET) \
		-Wall -Wextra -Wno-missing-declarations -Wno-unused-parameter \
		-DLOGGING=$(LOGGING) \
		-O2 -g -o $@ -c $< -I..
	llvm-strip -g $@

clean:
	$(RM) $(PROG).*.o

load: $(OBJ)
	$(SUDO) $(BPFTOOL) prog loadall $< /sys/fs/bpf/$(PROG) autoattach

unload:
	@$(SUDO) $(RM) -r -v /sys/fs/bpf/$(PROG)

test:
	@if $(SUDO) test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		env LOADED=1 bats ../tests/$(PROG).bats; \
	else \
		bats ../tests/$(PROG).bats; \
	fi
