#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([eaxsniff], [0.1], [/dev/null])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_INIT_AUTOMAKE

# Checks for libraries.

AC_CHECK_LIB([pcap], [pcap_lib_version], [], [
  AC_MSG_ERROR([Unable to find libpcap])
])

# Checks for header files.

AC_CHECK_HEADER([pcap/pcap.h], [], [
  AC_MSG_ERROR([Unable to find pcap/pcap.h])
])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
