Name:           laps4linux
Version:        1.5.3
Release:        1%{?dist}
Summary:        Laps4linux - auto-rotate the root password for AD bound (samba net, pbis, adcli) linux servers
BuildArch:      noarch

License:        GPL-3.0
URL:            https://github.com/schorschii/LAPS4LINUX
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 python3-pip krb5-devel python3-gssapi python3-ldap3 python3-wheel python3-cryptography python3-dns

%description
This RPM contains the script and personalized config to run the lap4linux python script


%prep
%setup -q

%build

%install
rpm -fr $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
cp usr/sbin/laps-runner.py $RPM_BUILD_ROOT/%{_sbindir}/laps-runner
cp usr/sbin/constants.py $RPM_BUILD_ROOT/%{_sbindir}/constants
cp usr/sbin/helpers.py $RPM_BUILD_ROOT/%{_sbindir}/helpers
cp usr/sbin/configuration.py $RPM_BUILD_ROOT/%{_sbindir}/configuration
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}
cp etc/laps-runner.json $RPM_BUILD_ROOT/%{_sysconfdir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/
cp etc/cron.hourly/laps-runner $RPM_BUILD_ROOT/%{_sysconfdir}/cron.hourly/

%clean
rm -rf $RPM_BUILD_ROOT


%files
%{_sbindir}/laps-runner
%{_sysconfdir}/laps-runner.json
%{_sysconfdir}/cron.hourly/laps-runner



%changelog
* August 2022 zbalkan
- Improved configuration handling
- Improved logging with global exception handling
- Removed unreachable code snippets
- Used stricter typing where possible
- Used external classes to simplify the code base
- Remmina check is moved to the menu creation. Instead of throwing exception on absence, it now does not render the menu at all.
- Added .editorconfig, .gitattributes, and requirements.txt for ease of development
- Added Github actions for static code analysis
- Ipdated README

* Thu Jan 13 2022 novaksam
- Initial build
