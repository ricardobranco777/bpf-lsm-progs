PROGS := lockdown_enforce \
	 path_restrict \
	 setuid_restrict \
	 userns_restrict

TARGETS	= all clean load unload enable disable status test
.PHONY: $(TARGETS)

all:	$(PROGS)

$(PROGS):
	$(MAKE) -C $@

$(TARGETS):
	@for dir in $(PROGS); do \
		$(MAKE) -C $$dir $@; \
	done
