ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/;s/s390x/s390/;s/ppc64le/powerpc/')
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
CLANG   ?= clang
CFLAGS  := -g -O2 -Wall -Wextra -Wno-missing-declarations

.PHONY: all clean load unload test

all:	$(PROG).bpf.o

vmlinux.h:
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(PROG).bpf.o: $(PROG).bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -Wno-unused-parameter -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

clean:
	$(RM) $(PROG).bpf.o vmlinux.h

unload load: SUDO := sudo

load: $(PROG).bpf.o
	$(SUDO) $(BPFTOOL) prog loadall $< /sys/fs/bpf/$(PROG) autoattach

unload:
	@$(SUDO) $(RM) -r -v /sys/fs/bpf/$(PROG)

test:
	@if sudo test -d /sys/fs/bpf/$(PROG) 2>/dev/null; then \
		$(SUDO) env LOADED=1 bats ../tests/$(PROG).bats; \
	else \
		$(SUDO) bats ../tests/$(PROG).bats; \
	fi
