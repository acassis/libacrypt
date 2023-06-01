bin_PROGRAMS = crypt cryptest

crypt_SOURCES = crypt_main.c
cryptest_SOURCES = crypt_test.c

crypt_LDADD = $(AM_LDADD) $(top_builddir)/lib/libacrypt.la
cryptest_LDADD = $(AM_LDADD) $(top_builddir)/lib/libacrypt.la

# Compiler options.
crypt_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/include
cryptest_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/include
cryptest_LDFLAGS = $(AM_LDFLAGS) -L$(top_srcdir)/ci -lunity
