Name:       capi-network-tethering
Summary:    Tethering Framework
Version:    0.0.12
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

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
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Tethering framework library

%prep
%setup -q

%build
%cmake .
make %{?jobs:-j%jobs}

%install
%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest capi-network-tethering.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so

%changelog
* Thu Feb 14 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.12-1
- APIs are exported
- LOG Format is changed
- fvisibility=hidden is applied and API's return value is checked

* Thu Jan 24 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.11-1
- Indications for Wi-Fi tethering setting change are added
- Dbus service / interface / object names are changed

* Tue Jan 15 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.10-1
- Wi-Fi tethering state is not checked when its settings are modified

* Fri Nov 02 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.9-1
- Manifest file is added for SMACK

* Mon Aug 20 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.8-1
- Deprecated APIs are removed

* Wed Aug 01 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.7-1
- Managed APIs are implemented for Wi-Fi tethering settings

* Sat Jul 21 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.6-1
- Fix tethering callback issue (JIRA S1-6197)

* Tue Jul 10 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.5
- Getting MAC address API is implemented
- TETHERING_TYPE_ALL case is implemented
- Test code is implemented

* Tue Jun 26 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.4
- All internal APIs are implemented

* Fri Jun 15 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.3
- Deprecated API from Glib2-2.32.3 is replaced with new one
