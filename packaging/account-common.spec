
Name:       account-common
Summary:    Account common library
Version:    0.1.1
Release:    1
Group:      Social & Content/API
License:    Apache-2.0
Source0:    account-common-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(glib-2.0) >= 2.26
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(key-manager)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  python-xml

%description
Account common libraryXB-Public-Package: no

%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Development files for %{name}

%prep
%setup -q

%post
/sbin/ldconfig
/usr/bin/sqlite3

chsmack -a '_' %{_libdir}/libaccount-common.so.0*

%postun
/sbin/ldconfig

%build
#export   CFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default"
#export CXXFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default -Wnon-virtual-dtor -Wno-c++0x-compat"
#export   CFLAGS+=" -Wno-unused-parameter -Wno-empty-body"
#export CXXFLAGS+=" -Wno-unused-parameter -Wno-empty-body"

#export   CFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow -fno-common"
#export CXXFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow"

#export CFLAGS="${CFLAGS} -fPIC -fvisibility=hidden"
export CFLAGS="${CFLAGS} -fPIC"
cmake . -DCMAKE_INSTALL_PREFIX=/usr \
		-DLIBDIR=%{_libdir} \
		-DBINDIR=%{_bindir} \
		-DINCLUDEDIR=%{_includedir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}
#mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants

rm -rf %{buildroot}%{_libdir}/account-common

%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%{_libdir}/pkgconfig/account-common.pc
%{_includedir}/*.h
