Summary: Alice Token Authorization Acc plugin
Name: xrootd-alicetokenacc
Version: 1.3.1
Release: 1%{?dist}
License: none
Group: CERN IT-ST

Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

AutoReqProv: no
Requires: xrootd-server >= 4.1.0
BuildRequires: xrootd-private-devel >= 4.1.0
BuildRequires: xrootd-devel >= 4.1.0
BuildRequires: xrootd-server-devel >= 4.1.0
BuildRequires: tokenauthz >= 1.1.8
BuildRequires: libxml2-devel, libcurl-devel

Requires: tokenauthz >= 1.1.8

%if %{?fedora}%{!?fedora:0} >= 21
BuildRequires: compat-openssl10-devel
%else
BuildRequires: openssl-devel
%endif

%description
An authorization plugin for xrootd using the Alice Token authorization envelope.

%prep
%setup -q
./bootstrap.sh

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --includedir=%{_includedir}
make
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/grid-security/xrootd/
cp -av .authz/xrootd/* $RPM_BUILD_ROOT/etc/grid-security/xrootd

find $RPM_BUILD_ROOT \( -type f -o -type l \) -print \
    | sed "s#^$RPM_BUILD_ROOT/*#/#" > RPM-FILE-LIST

%clean
rm -rf $RPM_BUILD_ROOT


%files -f RPM-FILE-LIST
%defattr(-,root,root,-)
%config %attr(644, root, root) /etc/grid-security/xrootd/TkAuthz.Authorization
%config %attr(444, root, root) /etc/grid-security/xrootd/privkey.pem
%config %attr(444, root, root) /etc/grid-security/xrootd/pubkey.pem
%doc


%changelog
* Fri Jan 27 2017 root <root@lxplus.cern.ch> - alicetokenacc-1.3.1
* Fri Aug 22 2008 root <root@pcitsmd01.cern.ch> - alicetokenacc-1
- Initial build.


