AC_INIT([crypt], [0.1], [acassis@gmail.com])
AC_PROG_CC
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([gnu subdir-objects])

# Add libraries dependance
AC_CONFIG_SUBDIRS([lib])

# Initialize libtool
LT_INIT

# Add src files
AC_CONFIG_FILES([Makefile
     lib/Makefile
     src/Makefile
     ])

AC_OUTPUT
