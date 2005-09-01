Summary:	Exim DSPAM at SMTP time
Name:		dspam-exim
Version:	0.8
Release:	1
License:	GPL
Group:		Networking/Daemons
# http://dspamwiki.woozle.org/DspamWithEximLocalScanSourceCodeNew
Source0:	dspam_exim.c
URL:		http://dspamwiki.woozle.org/DspamWithEximLocalScan
BuildRequires:	exim-devel
BuildRequires:	dspam-devel
BuildRequires:	clamav-devel
BuildRequires:	mysql-devel
Requires:	exim >= 2:4.52-4
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
Exim DSPAM at SMTP time.

%prep
%setup -q -T -c

%build
%{__cc} -Wall -DDLOPEN_LOCAL_SCAN=1 %{rpmcflags} %{rpmldflags} -fPIC \
        -I%{_includedir}/exim -I%{_includedir}/mysql -I%{_includedir}/clamav -I%{_includedir}/dspam \
	-lmysqlclient -lclamav -ldspam \
	-shared %{SOURCE0} -o dspam.so

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir}/mail,%{_libdir}/exim}

install dspam.so $RPM_BUILD_ROOT%{_libdir}/exim/dspam.so

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/exim/dspam.so
