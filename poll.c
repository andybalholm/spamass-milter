#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "subst_poll.h"

/* This function pulled from Markus Gutschke's "wy60" package */

/* $Id: poll.c,v 1.3 2003/03/11 03:40:27 dnelson Exp $ */

int poll(struct pollfd *fds, unsigned long nfds, int timeout) {
  // This emulation function is somewhat limited. Most notably, it will never
  // report POLLERR, POLLHUP, or POLLNVAL. The calling code has to detect
  // these error conditions by some other means (typically by read() or write()
  // reporting end-of-file).
  fd_set         readFds, writeFds, exceptionFds;
  struct timeval *timeoutPtr, timeoutStruct;
  int            i, rc, fd;

  FD_ZERO(&readFds);
  FD_ZERO(&writeFds);
  FD_ZERO(&exceptionFds);
  fd                      = -1;
  for (i = nfds; i--; ) {
    if (fds[i].events & POLLIN)
      FD_SET(fds[i].fd, &readFds);
    if (fds[i].events & POLLOUT)
      FD_SET(fds[i].fd, &writeFds);
    if (fds[i].events & POLLPRI)
      FD_SET(fds[i].fd, &exceptionFds);
    if (fds[i].fd > fd)
      fd                  = fds[i].fd;
    fds[i].revents        = 0;
  }
  if (timeout < 0)
    timeoutPtr            = NULL;
  else {
    timeoutStruct.tv_sec  =  timeout/1000;
    timeoutStruct.tv_usec = (timeout%1000) * 1000;
    timeoutPtr            = &timeoutStruct;
  }
  i                       = select(fd + 1, &readFds, &writeFds, &exceptionFds,
                                   timeoutPtr);
  if (i <= 0)
    rc                    = i;
  else {
    rc                    = 0;
    for (i = nfds; i--; ) {
      if (FD_ISSET(fds[i].fd, &readFds))
        fds[i].revents   |= POLLIN;
      if (FD_ISSET(fds[i].fd, &writeFds))
        fds[i].revents   |= POLLOUT;
      if (FD_ISSET(fds[i].fd, &exceptionFds))
        fds[i].revents   |= POLLPRI;
      if (fds[i].revents)
        rc++;
    }
  }
  return(rc);
}
