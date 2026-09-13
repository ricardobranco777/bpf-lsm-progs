PROGS := fs_mount_restrict \
	 setuid_restrict \
	 socket_create_restrict \
	 userns_restrict

TARGET    ?= /opt/bpf-lsm-progs
# Detect endianness
DEFAULT_BPFTARGET := $(shell [ "$$(printf '\1\2\3\4' | od -An -tx4 | tr -d ' ')" = "01020304" ] && echo bpfeb || echo bpfel)
BPFTARGET ?= $(DEFAULT_BPFTARGET)
SUDO      ?= sudo

TARGETS	= load unload test
.PHONY: all clean install uninstall $(TARGETS) $(PROGS)

all:	$(PROGS)

$(PROGS):
	@$(MAKE) --no-print-directory -C $@

clean:
	@for dir in $(PROGS); do \
		$(MAKE) --no-print-directory -C $$dir $@; \
	done
	$(RM) vmlinux.h

$(TARGETS):
	@for dir in $(PROGS); do \
		$(MAKE) --no-print-directory -C $$dir $@; \
	done

install: all
	@for p in $(PROGS); do \
		$(SUDO) install -D -m 644 "$$p/$$p.$(BPFTARGET).o" "$(TARGET)/$$p/$$p.$(BPFTARGET).o"; \
	done
	$(SUDO) $(MAKE) --no-print-directory -C initramfs install TARGET=$(TARGET) BPFTARGET=$(BPFTARGET) SUDO=$(SUDO)

uninstall:
	$(SUDO) rm -rf $(TARGET)
	$(SUDO) $(MAKE) --no-print-directory -C initramfs uninstall SUDO=$(SUDO)
