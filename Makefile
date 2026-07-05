PROGS := lockdown_enforce \
	 path_restrict \
	 setuid_restrict \
	 userns_restrict

.PHONY: all check clean load unload test

all:	$(PROGS)

# Note: .clang-format adapted from linux tree
check:
	@clang-format -n *.h */*.c

$(PROGS):
	$(MAKE) -C $@

all clean load unload test:
	@for dir in $(PROGS); do \
		$(MAKE) -C $$dir $@; \
	done
