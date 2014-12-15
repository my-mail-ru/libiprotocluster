%bcond_with static
%bcond_without graphite
%bcond_without my

Name:           libiprotocluster
Version:        %{__version}
Release:        %{__release}%{?dist}
Summary:        iproto C client library with cluster support

Group:          Development/Libraries
License:        BSD
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildRequires:  git
BuildRequires:  gcc cmake
BuildRequires:  libiproto-devel >= 2.0.4-2041
BuildRequires:  libiproto-static >= 2.0.4-2041
BuildRequires:  libev-devel >= 4.03
Requires:       libev >= 4.03

%description
iproto C client library with cluster support. Built from revision %{__revision}.

%prep
%setup -n iproto/cluster

%build
%cmake %{?!el7:-DLIBEV_INCLUDE_DIR:PATH=/usr/include/libev} %{?with_static:-DBUILD_SHARED_LIBS=OFF} %{?with_graphite:-DWITH_GRAPHITE=ON} %{?with_my:-DMY_MAIL_RU=ON} .
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%if ! %{with static}
%files
%{_libdir}/*.so
%endif

%package devel
Summary:  iproto C client library header files
Group:    Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: libiproto-devel

%description devel
iproto C client library header files. Built from revision %{__revision}.

%files devel
%{_includedir}/*

%package static
Summary: iproto C client library static libraries
Group:   Development/Libraries

%description static
iproto C client library static libraries. Built from revision %{__revision}.

%if %{with static}
%files static
%{_libdir}/*.a
%endif

%changelog
* Mon Dec 10 2012 Aleksey Mashanov <a.mashanov@corp.mail.ru>
- Initial release
