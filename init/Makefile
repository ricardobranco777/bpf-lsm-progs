# SPDX-License-Identifier: BSD-2-Clause
SUDO ?= sudo

# Active runit service directory: /run/runit/service on Artix, /var/service
# on Void, /etc/service on some other setups. Whichever exists first wins.
RUNIT_SVDIR := $(shell for d in /run/runit/service /var/service /etc/service; do \
	[ -d "$$d" ] && { echo "$$d"; break; }; done)

.PHONY: install install-systemd install-openrc install-runit install-sysvinit install-dinit \
	uninstall uninstall-systemd uninstall-openrc uninstall-runit uninstall-sysvinit uninstall-dinit

install:
	@if [ -d /run/systemd/system ]; then \
		$(MAKE) --no-print-directory install-systemd; \
	elif command -v rc-service >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory install-openrc; \
	elif [ -d /etc/runit ]; then \
		$(MAKE) --no-print-directory install-runit; \
	elif command -v update-rc.d >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory install-sysvinit; \
	elif command -v dinitctl >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory install-dinit; \
	else \
		echo "No supported init system found (systemd, OpenRC, runit, SysVinit, dinit)." >&2; \
		exit 1; \
	fi

install-systemd:
	$(SUDO) cp systemd/bpf-tracepipe.service /etc/systemd/system/
	$(SUDO) systemctl enable --now bpf-tracepipe.service

install-openrc:
	$(SUDO) cp openrc/bpf-tracepipe /etc/init.d/
	$(SUDO) rc-update add bpf-tracepipe default
	$(SUDO) rc-service bpf-tracepipe start

install-runit:
	@test -n "$(RUNIT_SVDIR)" || { echo "Could not find the active runit service directory (checked /run/runit/service, /var/service, /etc/service)." >&2; exit 1; }
	$(SUDO) cp -r runit/bpf-tracepipe /etc/sv/
	$(SUDO) ln -sf /etc/sv/bpf-tracepipe /etc/runit/runsvdir/default/
	$(SUDO) ln -sf /etc/sv/bpf-tracepipe $(RUNIT_SVDIR)/

install-sysvinit:
	$(SUDO) install -m 755 sysvinit/bpf-tracepipe /etc/init.d/bpf-tracepipe
	$(SUDO) update-rc.d bpf-tracepipe defaults
	$(SUDO) service bpf-tracepipe start

install-dinit:
	$(SUDO) cp dinit/bpf-tracepipe /etc/dinit.d/
	$(SUDO) dinitctl enable bpf-tracepipe

uninstall:
	@if [ -d /run/systemd/system ]; then \
		$(MAKE) --no-print-directory uninstall-systemd; \
	elif command -v rc-service >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory uninstall-openrc; \
	elif [ -d /etc/runit ]; then \
		$(MAKE) --no-print-directory uninstall-runit; \
	elif command -v update-rc.d >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory uninstall-sysvinit; \
	elif command -v dinitctl >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory uninstall-dinit; \
	else \
		echo "No supported init system found (systemd, OpenRC, runit, SysVinit, dinit)." >&2; \
		exit 1; \
	fi

uninstall-systemd:
	$(SUDO) systemctl disable --now bpf-tracepipe.service
	$(SUDO) rm -f /etc/systemd/system/bpf-tracepipe.service

uninstall-openrc:
	$(SUDO) rc-service bpf-tracepipe stop
	$(SUDO) rc-update del bpf-tracepipe default
	$(SUDO) rm -f /etc/init.d/bpf-tracepipe

uninstall-runit:
	@test -n "$(RUNIT_SVDIR)" || { echo "Could not find the active runit service directory (checked /run/runit/service, /var/service, /etc/service)." >&2; exit 1; }
	$(SUDO) sv down bpf-tracepipe
	$(SUDO) rm -f $(RUNIT_SVDIR)/bpf-tracepipe
	$(SUDO) rm -f /etc/runit/runsvdir/default/bpf-tracepipe
	$(SUDO) rm -rf /etc/sv/bpf-tracepipe

uninstall-sysvinit:
	$(SUDO) service bpf-tracepipe stop
	$(SUDO) update-rc.d -f bpf-tracepipe remove
	$(SUDO) rm -f /etc/init.d/bpf-tracepipe

uninstall-dinit:
	$(SUDO) dinitctl stop bpf-tracepipe
	$(SUDO) dinitctl disable bpf-tracepipe
	$(SUDO) rm -f /etc/dinit.d/bpf-tracepipe
