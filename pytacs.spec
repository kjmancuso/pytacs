%define product pytacs
%define version 0.0.1
%define release 1
%{expand: %%define pyver %(python -c 'import sys;print(sys.version[0:3])')}
%define pysite %{_libdir}/python%{pyver}/site-packages

Summary: PyTACS Python Tacacs+ System
Name: %{product}
Version: %{version}
Release: %{release}
BuildArch: noarch
License: LGPL
URL: http://pytacs.sourceforge.net
Group: Servers
Source0: %{product}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: python >= 2.3.4 python-ldap >= 2.0

%description
PyTACS is a tacacs+ compatible server and client/server library written in python.

%package lib
Summary: PyTACS Python Tacacs+ Library
Group: Servers
Requires: python >= 2.3.4

%description lib
PyTACS Lib is a tacacs+ compatible library written in Python.

%package server
Summary: PyTACS Python Tacacs+ Server
Group: Servers
Requires: %{product}-lib = %{version}
Requires: python >= 2.3.4 python-ldap >= 2.0

%description server
PyTACS Server is a tacacs+ compatible server written in Python. User authentication and authorisation sources are easily configured and new sources can easily be created and added.

%prep
%setup -q -n %{product}

%build

%install
rm -rf %{buildroot}
%{__install} -d -m 755 -o root -g root %{buildroot}/etc/init.d
%{__install} -m 644 -o root -g root %{name}.init %{buildroot}/etc/init.d/%{name}
%{__install} -m 644 -o root -g root %{name}.conf %{buildroot}/etc/%{name}.conf
%{__install} -d -m 755 -o root -g root %{buildroot}/etc/%{name}.d
%{__install} -d -m 755 -o root -g root %{buildroot}/%{_sbindir}
%{__install} -m 755 -o root -g root %{name}.py %{buildroot}/%{_sbindir}/%{name}
%{__install} -d -m 755 -o root -g root %{buildroot}/%{pysite}/%{name}
%{__install} -m 644 -o root -g root %{name}/__init__.py %{buildroot}/%{pysite}/%{name}/__init__.py

%post server
if [ $1 == 1]; then
	chkconfig --add %{name}
	/etc/init.d/%{name} condrestart
fi

%preun server
if [ $1 == 0 ]; then
	service %{name} stop
	chkconfig --del %{name}
fi

%files lib
%defattr(-, root, root, 0644)
%{pysite}/%{name}
%doc COPYING
%doc draft-grant-tacacs-02.txt

%files server
%defattr(-, root, root, 0755)
/etc/init.d/%{name}
/etc/%{name}.conf
/etc/%{name}.d/
/%{_sbindir}/%{name}
%doc COPYING

%changelog
* Tue Jun 14 2011 Adrian Hungate <adrian@tlspu.com>
- Update packaging for new email address(es)
* Sun Mar 29 2009 Adrian Hungate <adrian@haqa.co.uk>
- First RPM packaging of %{name}
