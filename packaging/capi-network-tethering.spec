Name:		capi-network-tethering
Summary:	Tethering Framework
Version:	1.0.27
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(capi-base-common)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(key-manager)
BuildRequires:	pkgconfig(libssl)
BuildRequires:	pkgconfig(capi-system-info)
BuildRequires:	cmake
Requires(post):		/sbin/ldconfig
Requires(postun):	/sbin/ldconfig

%description
Tethering framework library for CAPI

%package devel
Summary:	Development package for Tethering framework library
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Tethering framework library

%prep
%setup -q


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake -DCMAKE_BUILD_TYPE="Private" \
%if "%{?profile}" == "wearable"
	-DTIZEN_WEARABLE=1 \
%else
%if "%{?profile}" == "mobile"
	-DTIZEN_MOBILE=1 \
%endif
%endif
%ifarch %{arm}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=arm \
%else
%if 0%{?simulator}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=emul \
%else
	-DCMAKE_BUILD_TYPE="Private" -DARCH=i586 \
%endif
%endif
	.

make %{?_smp_mflags}


%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-tethering
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-tethering-devel

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest capi-network-tethering.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so.*
/usr/share/license/capi-network-tethering
%{_bindir}/tethering_test
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
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so
/usr/share/license/capi-network-tethering-devel
