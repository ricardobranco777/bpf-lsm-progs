TARGET    ?= /opt/bpf-lsm-progs
BPFTARGET ?= bpfel
SUDO      ?= sudo

.PHONY: install install-dracut install-mkinitcpio install-initramfs-tools \
	uninstall uninstall-dracut uninstall-mkinitcpio uninstall-initramfs-tools

install:
	@if command -v dracut >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory install-dracut TARGET=$(TARGET) BPFTARGET=$(BPFTARGET); \
	elif command -v mkinitcpio >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory install-mkinitcpio TARGET=$(TARGET) BPFTARGET=$(BPFTARGET); \
	elif [ -d /etc/initramfs-tools ]; then \
		$(MAKE) --no-print-directory install-initramfs-tools TARGET=$(TARGET) BPFTARGET=$(BPFTARGET); \
	elif command -v mkinitfs >/dev/null 2>&1; then \
		echo "Alpine's mkinitfs has no hook mechanism for this -- see" >&2; \
		echo "https://gitlab.alpinelinux.org/alpine/mkinitfs/-/issues/18" >&2; \
		exit 1; \
	else \
		echo "No supported initramfs generator found (dracut, mkinitcpio, initramfs-tools)." >&2; \
		exit 1; \
	fi

install-dracut:
	$(SUDO) cp -r dracut/91bpf-lsm /usr/lib/dracut/modules.d/
	$(SUDO) sed -i \
		-e 's|^SRCDIR=.*|SRCDIR="$(TARGET)"|' \
		-e 's|^BPFTARGET=.*|BPFTARGET="$(BPFTARGET)"|' \
		/usr/lib/dracut/modules.d/91bpf-lsm/module-setup.sh
	$(SUDO) sed -i 's|^BPFTARGET=.*|BPFTARGET="$(BPFTARGET)"|' \
		/usr/lib/dracut/modules.d/91bpf-lsm/bpf-lsm-load.sh
	echo 'add_dracutmodules+=" bpf-lsm "' | $(SUDO) tee /etc/dracut.conf.d/bpf-lsm.conf >/dev/null
	#$(SUDO) dracut -f

install-mkinitcpio:
	$(SUDO) install -m 755 mkinitcpio/install/bpf-lsm /etc/initcpio/install/bpf-lsm
	$(SUDO) install -m 644 mkinitcpio/hooks/bpf-lsm /etc/initcpio/hooks/bpf-lsm
	$(SUDO) install -m 755 mkinitcpio/systemd/bpf-lsm-load.sh /etc/initcpio/bpf-lsm-load.sh
	$(SUDO) install -m 644 mkinitcpio/systemd/bpf-lsm.service /etc/initcpio/bpf-lsm.service
	$(SUDO) sed -i \
		-e 's|^\([[:space:]]*\)local srcdir=.*|\1local srcdir=$(TARGET)|' \
		-e 's|^\([[:space:]]*\)local bpftarget=.*|\1local bpftarget=$(BPFTARGET)|' \
		/etc/initcpio/install/bpf-lsm
	$(SUDO) sed -i 's|^\([[:space:]]*\)local bpftarget=.*|\1local bpftarget=$(BPFTARGET)|' \
		/etc/initcpio/hooks/bpf-lsm
	$(SUDO) sed -i 's|^bpftarget=.*|bpftarget=$(BPFTARGET)|' \
		/etc/initcpio/bpf-lsm-load.sh
	@if ! grep -q '\bbpf-lsm\b' /etc/mkinitcpio.conf; then \
		$(SUDO) sed -i '/^HOOKS=/s/)$$/ bpf-lsm)/' /etc/mkinitcpio.conf; \
	fi
	@if grep -q '\bbpf-lsm\b' /etc/mkinitcpio.conf; then \
		: ; \
	else \
		echo "Couldn't add bpf-lsm to HOOKS=(...) automatically (unusual" >&2; \
		echo "formatting?) -- add it to /etc/mkinitcpio.conf yourself (after" >&2; \
		echo "'filesystems' is typical), then re-run 'make install' (or" >&2; \
		echo "'sudo mkinitcpio -P' yourself)." >&2; \
		exit 1; \
	fi
	$(SUDO) mkinitcpio -P

install-initramfs-tools:
	$(SUDO) install -m 755 initramfs-tools/hooks/bpf-lsm /etc/initramfs-tools/hooks/bpf-lsm
	$(SUDO) install -m 755 initramfs-tools/scripts/init-bottom/bpf-lsm /etc/initramfs-tools/scripts/init-bottom/bpf-lsm
	$(SUDO) sed -i \
		-e 's|^SRCDIR=.*|SRCDIR="$(TARGET)"|' \
		-e 's|^BPFTARGET=.*|BPFTARGET="$(BPFTARGET)"|' \
		/etc/initramfs-tools/hooks/bpf-lsm
	$(SUDO) sed -i \
		-e 's|^SRCDIR=.*|SRCDIR="$(TARGET)"|' \
		-e 's|^BPFTARGET=.*|BPFTARGET="$(BPFTARGET)"|' \
		/etc/initramfs-tools/scripts/init-bottom/bpf-lsm
	$(SUDO) update-initramfs -u

uninstall:
	@if command -v dracut >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory uninstall-dracut; \
	elif command -v mkinitcpio >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory uninstall-mkinitcpio; \
	elif [ -d /etc/initramfs-tools ]; then \
		$(MAKE) --no-print-directory uninstall-initramfs-tools; \
	else \
		echo "No supported initramfs generator found (dracut, mkinitcpio, initramfs-tools)." >&2; \
		exit 1; \
	fi

uninstall-dracut:
	$(SUDO) rm -rf /usr/lib/dracut/modules.d/91bpf-lsm
	$(SUDO) rm -f /etc/dracut.conf.d/bpf-lsm.conf
	$(SUDO) dracut -vf

uninstall-mkinitcpio:
	$(SUDO) rm -f /etc/initcpio/install/bpf-lsm /etc/initcpio/hooks/bpf-lsm \
		/etc/initcpio/bpf-lsm-load.sh /etc/initcpio/bpf-lsm.service
	@if grep -q '\bbpf-lsm\b' /etc/mkinitcpio.conf; then \
		$(SUDO) sed -i '/^HOOKS=/{s/ bpf-lsm\b//; s/\bbpf-lsm //}' /etc/mkinitcpio.conf; \
	fi
	@if grep -q '\bbpf-lsm\b' /etc/mkinitcpio.conf; then \
		echo "Couldn't remove bpf-lsm from HOOKS=(...) automatically (unusual" >&2; \
		echo "formatting?) -- remove it from /etc/mkinitcpio.conf yourself, then" >&2; \
		echo "run 'sudo mkinitcpio -P' yourself." >&2; \
	fi
	$(SUDO) mkinitcpio -P

uninstall-initramfs-tools:
	$(SUDO) rm -f /etc/initramfs-tools/hooks/bpf-lsm /etc/initramfs-tools/scripts/init-bottom/bpf-lsm
	$(SUDO) update-initramfs -u
