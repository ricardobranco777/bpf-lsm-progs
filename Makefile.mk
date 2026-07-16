BPFTOOL   ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG     ?= clang
BPFTARGET ?= bpfel
OBJ       := $(PROG).$(BPFTARGET).o
SUDO      := sudo

.PHONY: all clean load unload test

all:	$(OBJ)

../vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).$(BPFTARGET).o: $(PROG).bpf.c ../vmlinux.h
	$(CLANG) -target $(BPFTARGET) \
		-Wall -Wextra -Wno-missing-declarations -Wno-unused-parameter \
		-O2 -g -o $@ -c $<
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
