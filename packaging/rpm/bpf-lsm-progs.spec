%global debug_package %{nil}

Name:           bpf-lsm-progs
Version:        0.4.0
Release:        1
Summary:        BPF LSM programs for Linux security policy enforcement
# BPF bytecode is a virtual ISA -- the only per-machine variable is byte
# order, not CPU architecture. Both bpfel and bpfeb objects are built and
# shipped together (see %%build), and the install-time hook scripts
# already auto-detect which one the target machine needs, so one noarch
# package covers every architecture.
BuildArch:      noarch

License:        BSD-2-Clause
URL:            https://github.com/ricardobranco777/bpf-lsm-progs
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  bpftool
BuildRequires:  clang
BuildRequires:  libbpf-devel
BuildRequires:  llvm
BuildRequires:  make

Requires:       make

%description
BPF LSM programs enforcing Linux security policy: deny creation of
legacy/niche socket address families and IP protocols with a history of
local memory-safety bugs, deny mounting legacy/niche filesystem types,
restrict unprivileged user namespace creation, and block setuid/setgid
bit creation for non-root processes.

%prep
%autosetup

%build
make %{?_smp_mflags}
make %{?_smp_mflags} BPFTARGET=bpfeb

%install
rm -rf %{buildroot}
for p in fs_mount_restrict setuid_restrict socket_create_restrict userns_restrict; do
	for bpftarget in bpfel bpfeb; do
		install -D -m 0644 "$p/$p.$bpftarget.o" "%{buildroot}/opt/%{name}/$p/$p.$bpftarget.o"
	done
done
cp -a initramfs %{buildroot}/opt/%{name}/
cp -a init %{buildroot}/opt/%{name}/

%post
# The bpf-tracepipe logging service (init/) is opt-in, same as with a
# manual "make install": run "make -C /opt/%{name}/init install"
# yourself if you want trace_pipe denials forwarded to your log.
make -C /opt/%{name}/initramfs install SUDO= TARGET=/opt/%{name}

%preun
if [ "$1" -eq 0 ]; then
	make -C /opt/%{name}/initramfs uninstall SUDO=
fi

%files
%license LICENSE
%doc README.md DOCS.md FAQ.md
/opt/%{name}

%changelog
* Fri Sep 11 2026 Ricardo Branco <rbranco@suse.de> - 0.4.0-1
- Initial packaging.
