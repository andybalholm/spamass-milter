## ----------------------------------- ##
## Check if --with-dmalloc was given.  ##
## ----------------------------------- ##

# serial 1

AC_DEFUN([DN_WITH_DMALLOC],
[AC_MSG_CHECKING([if malloc debugging is wanted])
AC_ARG_WITH(dmalloc,
[  --with-dmalloc          use dmalloc ( http://www.dmalloc.com )],
[if test "$withval" = yes; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(WITH_DMALLOC,1,
            [Define if using the dmalloc debugging malloc package])
  AC_CHECK_HEADERS(dmalloc.h)
  AC_CHECK_LIB(dmallocthcxx, dmalloc_malloc,,AC_MSG_ERROR([Threaded C++ dmalloc library not found]))
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])
