dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/htmldoc/ac_cxx_verbose_terminate_handler.html
dnl
dnl $Id: ac_cxx_verbose_terminate_handler.m4,v 1.1 2003/10/24 06:55:14 dnelson Exp $
AC_DEFUN([AC_CXX_VERBOSE_TERMINATE_HANDLER],
[AC_CACHE_CHECK(whether the compiler has __gnu_cxx::__verbose_terminate_handler,
ac_cv_verbose_terminate_handler,
[
  AC_REQUIRE([AC_CXX_EXCEPTIONS])
  AC_REQUIRE([AC_CXX_NAMESPACES])
  AC_LANG_SAVE
  AC_LANG_CPLUSPLUS
  AC_TRY_COMPILE(
    [#include <exception>], [std::set_terminate(__gnu_cxx::__verbose_terminate_handler);],
    ac_cv_verbose_terminate_handler=yes, ac_cv_verbose_terminate_handler=no
  )
  AC_LANG_RESTORE
])
if test "$ac_cv_verbose_terminate_handler" = yes; then
  AC_DEFINE(HAVE_VERBOSE_TERMINATE_HANDLER, , [define if the compiler has __gnu_cxx::__verbose_terminate_handler])
fi
])
