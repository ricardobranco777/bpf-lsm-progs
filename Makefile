PROGS := setuid_restrict \
	 userns_restrict

TARGET    ?= /opt/bpf-lsm-progs
BPFTARGET ?= bpfel
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
	$(SUDO) $(MAKE) --no-print-directory -C initramfs install TARGET=$(TARGET) BPFTARGET=$(BPFTARGET)

uninstall:
	$(SUDO) rm -rf $(TARGET)
	$(SUDO) $(MAKE) --no-print-directory -C initramfs uninstall
