dnl AC_PIKE_PATHS, taken from the Pike 7.5 distribution at http://pike.ida.liu.se
dnl $Id: ac_pike_paths.m4,v 1.1 2003/06/18 18:57:57 dnelson Exp $

AC_DEFUN([PIKE_INCLUDE_PATHS],
[
#############################################################################
## Search for some popular places where libraries may be hidden.
#############################################################################

AC_MSG_NOTICE([Scanning for include-file directories:])

#Don't add include dirs if they give us warnings...
OLD_ac_c_preproc_warn_flag="$ac_c_preproc_warn_flag"
ac_c_preproc_warn_flag=yes

real_include_dirs=''
for d in \
  `echo $prefix | sed "s@^NONE@$ac_default_prefix@g"`/include \
  /usr/local/include /sw/local/include \
  /usr/gnu/include /opt/gnu/include \
  /sw/gnu/include /sw/include \
  /usr/freeware/include /usr/pkg/include \
  /opt/sfw/include 
do
  AC_MSG_CHECKING($d)
  case x$d in
    x/usr/include | x/usr//include)
    ;;
    *)
      if test -d "$d/." ; then
        REALDIR="`cd $d/. ; /bin/pwd`"
        if test "x$REALDIR" = x ; then
          REALDIR=UNKNOWN
        else
          :
        fi

        case " $CPPFLAGS $real_include_dirs " in
          *\ -I$d\ * | *\ -I$REALDIR\ *)
             AC_MSG_RESULT(already added)
          ;;
          *)
     OLD_CPPFLAGS="${CPPFLAGS}"
            CPPFLAGS="${CPPFLAGS} -I$d"
     AC_TRY_CPP([#include <stdio.h>], [
              AC_MSG_RESULT(added)
              if test "x$REALDIR" != xUNKNOWN; then
                real_include_dirs="${real_include_dirs} -I$REALDIR"
              else
                :
              fi
     ], [
       AC_MSG_RESULT(fails)
       CPPFLAGS="${OLD_CPPFLAGS}"
     ])
          ;;
        esac
      else
        AC_MSG_RESULT(no)
      fi
    ;;
  esac
done

#Restore preprocessor warning sensitivity
ac_c_preproc_warn_flag="$OLD_ac_c_preproc_warn_flag"

])

AC_DEFUN([PIKE_LIBRARY_PATHS],
[

AC_MSG_NOTICE([Scanning for library directories:])
for dd in \
  `echo $exec_prefix | sed "s@^NONE@$prefix/lib@g" | sed "s@^NONE@$ac_default_prefix@g"` \
  /usr/local/lib /sw/local/lib /sw/lib \
  /usr/gnu/lib /opt/gnu/lib /sw/gnu/lib \
  /usr/freeware/lib /usr/pkg/lib \
  /opt/sfw/lib 
do
  if test x"$dd" = x"/lib"; then continue; fi
  if test x"$dd" = x"/usr/lib"; then continue; fi
  for suff in '' 32 64 '/64'; do
    d="$dd$suff"
    AC_MSG_CHECKING($d)
    if test -d "$d/." ; then
	case " $LDFLAGS " in
	  *\ -L$d\ -R$d\ * | *\ -R$d\ -L$d\ *)
	    AC_MSG_RESULT(already added)
	  ;;
	  *)
	    OLD_LDFLAGS="${LDFLAGS}"
	    LDFLAGS="${LDFLAGS} -R$d -L$d -lm"
	    AC_TRY_RUN([
#include <stdio.h>
#include <math.h>
int main(int argc, char **argv)
{
  double (*foo)(double) = ceil;
  exit(0);
}
	    ],[ LDFLAGS="$OLD_LDFLAGS -R$d -L$d"
		AC_MSG_RESULT(yes)
	    ],[ LDFLAGS="$OLD_LDFLAGS"
		AC_MSG_RESULT(no)
	    ],[AC_TRY_LINK([
#include <stdio.h>
#include <math.h>
	       ],[
		 double (*foo)(double) = ceil;
		 exit(0);
	       ],[ LDFLAGS="$OLD_LDFLAGS -R$d -L$d"
		   AC_MSG_RESULT(probably)
	       ],[ LDFLAGS="$OLD_LDFLAGS"
		   AC_MSG_RESULT(no)])])
	  ;;
	esac
    else
	AC_MSG_RESULT(no)
    fi
  done
done

])
