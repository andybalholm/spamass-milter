dnl AC_SYS_COMPILER_FLAG, taken from the Pike 7.5 distribution at http://pike.ida.liu.se
dnl $Id: ac_pike_compiler_flag.m4,v 1.2 2003/10/24 06:53:51 dnelson Exp $

# option, cache_name, variable, do_if_failed, do_if_ok
AC_DEFUN(AC_PIKE_COMPILER_FLAG,
[
  AC_MSG_CHECKING(for $1)
  AC_CACHE_VAL(pike_cv_option_$2,
  [
    OLD_CPPFLAGS="[$]CPPFLAGS"
    CPPFLAGS="[$]OLD_CPPFLAGS $1"
    old_ac_link="[$]ac_link"
    ac_link="[$]old_ac_link 2>conftezt.out.2"
    AC_TRY_RUN([
      int foo;
      int main(int argc, char **argv)
      {
        /* The following code triggs gcc:s generation of aline opcodes,
	 * which some versions of as does not support.
	 */
	if (argc > 0) argc = 0;
	return argc;
      }
    ],pike_cv_option_$2=yes,
      pike_cv_option_$2=no, [
      AC_TRY_LINK([], [], pike_cv_option_$2=yes, pike_cv_option_$2=no)
    ])
    if grep -i 'unrecognized option' <conftezt.out.2 >/dev/null; then
      pike_cv_option_$2=no
    elif grep -i 'unknown option' <conftezt.out.2 >/dev/null; then
      # cc/HPUX says the following regarding -q64:
      #
      # cc: warning 422: Unknown option "6" ignored.
      # cc: warning 422: Unknown option "4" ignored.
      pike_cv_option_$2=no
    elif grep -i 'optimizer bugs' <conftezt.out.2 >/dev/null; then
      # gcc/FreeBSD-4.6/alpha says the following regarding -O2:
      #
      # cc1: warning: 
      # ***
      # ***     The -O2 flag TRIGGERS KNOWN OPTIMIZER BUGS ON THIS PLATFORM
      # ***
      pike_cv_option_$2=no
    elif grep -i 'not found' <conftezt.out.2 >/dev/null; then
      # cc/AIX says the following regarding +O3:
      #
      # cc: 1501-228 input file +O3 not found
      pike_cv_option_$2=no
    elif grep -i 'ignored' <conftezt.out.2 >/dev/null; then
      # gcc/AIX says the following regarding -fpic:
      #
      # cc1: warning: -fpic ignored (all code is position independent)
      pike_cv_option_$2=no
    else :; fi
    rm conftezt.out.2
    CPPFLAGS="[$]OLD_CPPFLAGS"
    ac_link="[$]old_ac_link"
  ])
  
  if test x"[$]pike_cv_option_$2" = "xyes" ; then
    $3="[$]$3 $1"
    case "$3" in
      OPTIMIZE)
        CFLAGS="[$]CFLAGS $1"
      ;;
    esac
    AC_MSG_RESULT(yes)
    $5
  else
    AC_MSG_RESULT(no)
    $4
  fi
])
