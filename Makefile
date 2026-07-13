PROGS := lockdown_enforce \
	 setuid_restrict \
	 userns_restrict

TARGETS	= load unload enable disable status test
.PHONY: all clean $(TARGETS) $(PROGS)

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
