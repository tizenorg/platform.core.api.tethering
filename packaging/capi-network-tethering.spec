Name:       capi-network-tethering
Summary:    Tethering Framework
Version:    0.0.15
Release:    1
Group:      Connectivity/API
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	capi-network-tethering.manifest

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(vconf)
BuildRequires: cmake

%description
Tethering framework library for CAPI

%package devel
Summary:	Development package for Tethering framework library
Group:		Connectivity/Development
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Tethering framework library

%prep
%setup -q
cp %{SOURCE1001} .

%build
%ifarch %{arm}
%cmake . -DARCH=arm
%else
%if 0%{?simulator}
%cmake . -DARCH=emul
%else
%cmake . -DARCH=i586
%endif
%endif
make %{?jobs:-j%jobs}

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so.*
/usr/share/license/%{name}
%ifarch %{arm}
/etc/config/connectivity/sysinfo-tethering.xml
%else
%if 0%{?simulator}
# Noop
%else
/etc/config/connectivity/sysinfo-tethering.xml
%endif
%endif

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so

