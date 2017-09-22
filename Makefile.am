#######################################################################
## Makefile.am for AliceTokenACC plugin
##
##
## Version info: $Id: Makefile.am,v 1.5 2006/07/24 07:38:57 dfeich Exp $
## Checked in by $Author: apeters $
#######################################################################

lib_LTLIBRARIES = libXrdAliceTokenAcc.la

INCLUDES = -I$(XROOTD_LOCATION)/include/xrootd -I$(OPENSSL_INCDIR) -I$(TKAUTHZ_INCDIR)

libXrdAliceTokenAcc_la_SOURCES = \
	XrdAliceTokenAcc.cc \
	XrdAliceTokenAcc.hh 

libXrdAliceTokenAcc_la_LIBADD = -L$(XROOTD_LOCATION)/lib$(MARK64)/  -lXrdUtils -L$(OPENSSL_LIBDIR)/ -lcrypto -L$(TKAUTHZ_LIBDIR)/ -lTokenAuthz

EXTRA_DIST = configure.ac configure bootstrap.sh xrootd-alicetokenacc.spec .authz

rpm:	dist
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp $(DIST_ARCHIVES) ~/rpmbuild/SOURCES/
	rpmbuild -bb --define "debug_package %{nil}" --define "_rpmdir ./RPMS/" --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" xrootd-alicetokenacc.spec

