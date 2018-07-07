//
//
//  $Id: spamass-milter.cpp,v 1.100 2014/08/15 02:46:50 kovert Exp $
//
//  SpamAss-Milter
//    - a rather trivial SpamAssassin Sendmail Milter plugin
//
//  for information about SpamAssassin please see
//                        http://www.spamassassin.org
//
//  for information about Sendmail please see
//                        http://www.sendmail.org
//
//  Copyright (c) 2002 Georg C. F. Greve <greve@gnu.org>,
//   all rights maintained by FSF Europe e.V.,
//   Villa Vogelsang, Antonienallee 1, 45279 Essen, Germany
//

// {{{ License, Contact, Notes & Includes

//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 2 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the Free Software
//   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//   Contact:
//            Michael Brown <michaelb@opentext.com>
//

// Notes:
//
//  The libmilter for sendmail works callback-oriented, so if you have no
//  experience with event-driven programming, the following may be hard for
//  you to understand.
//
//  The code should be reasonably thread-safe. No guarantees, though.
//
//  This program roughly does the following steps:
//
//   1. register filter with libmilter & set up socket
//   2. register the callback functions defined in this file
//    -- wait for mail to show up --
//   3. start spamc client
//   4. assemble mail since libmilter passes it in pieces and put
//      these parts in the output pipe to spamc.
//   5. when the mail is complete, close the pipe.
//   6. read output from spamc, close input pipe and clean up PID
//   7. check for the flags affected by SpamAssassin and set/change
//      them accordingly
//   8. replace the body with the one provided by SpamAssassin if the
//      mail was rated spam, unless -m is specified
//   9. free all temporary data
//   10. tell sendmail to let the mail to go on (default) or be discarded
//    -- wait for mail to show up -- (restart at 3)
//

// Includes
#include "config.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#else
#include "subst_poll.h"
#endif
#include <errno.h>
#include <netdb.h>
#include <grp.h>

// C++ includes
#include <cstdio>
#include <cstddef>
#include <csignal>
#include <string>
#include <iostream>

#ifdef  __cplusplus
extern "C" {
#endif

#include "libmilter/mfapi.h"
//#include "libmilter/mfdef.h"

#if !HAVE_DECL_STRSEP
char *strsep(char **stringp, const char *delim);
#endif

#if !HAVE_DECL_DAEMON
int daemon(int nochdir, int noclose);
#endif

#ifdef  __cplusplus
}
#endif

#include "spamass-milter.h"

#ifdef WITH_DMALLOC
#include "dmalloc.h"
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7F000001
#endif

// }}}

static const char Id[] = "$Id: spamass-milter.cpp,v 1.100 2014/08/15 02:46:50 kovert Exp $";

static char FilterName[] = "SpamAssassin";

struct smfiDesc smfilter =
  {
    FilterName, // filter name
    SMFI_VERSION,   // version code -- leave untouched
    SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_CHGBODY,  // flags
    mlfi_connect, // info filter callback
    mlfi_helo, // HELO filter callback
    mlfi_envfrom, // envelope sender filter callback
    mlfi_envrcpt, // envelope recipient filter callback
    mlfi_header, // header filter callback
    mlfi_eoh, // end of header callback
    mlfi_body, // body filter callback
    mlfi_eom, // end of message callback
    mlfi_abort, // message aborted callback
    mlfi_close, // connection cleanup callback
  };

const char *const debugstrings[] = {
	"ALL", "FUNC", "POLL", "UORI", "STR", "MISC", "NET", "SPAMC", "RCPT",
	"COPY",
	NULL
};

int flag_debug = (1<<D_ALWAYS);
bool flag_reject = false;
int reject_score = -1;
bool dontmodifyspam = false;    // Don't modify/add body or spam results headers
bool dontmodify = false;        // Don't add SA headers, ever.
bool flag_sniffuser = false;
char *defaultuser;				/* Username to send to spamc if there are multiple recipients */
char *defaultdomain;			/* Domain to append if incoming address has none */
char *path_to_sendmail = (char *) SENDMAIL;
char *spamdhost;
char *rejecttext = NULL;				/* If we reject a mail, then use this text */
char *rejectcode = NULL;				/* If we reject a mail, then use code */
struct networklist ignorenets;
struct addresslist ignoreaddrs;
int spamc_argc;
char **spamc_argv;
bool flag_bucket = false;
bool flag_bucket_only = false;
char *spambucket;
bool flag_full_email = false;		/* pass full email address to spamc */
bool flag_expand = false;	/* alias/virtusertable expansion */
bool warnedmacro = false;	/* have we logged that we couldn't fetch a macro? */
bool auth = false;		/* don't scan authenticated users */

// {{{ main()

int
main(int argc, char* argv[])
{
   int c, err = 0;
   const char *args = "afd:mMp:P:r:u:D:i:b:B:e:xS:R:C:g:T:";
   char *sock = NULL;
   char *group = NULL;
   bool dofork = false;
   char *pidfilename = NULL;
   FILE *pidfile = NULL;

#ifdef HAVE_VERBOSE_TERMINATE_HANDLER
	std::set_terminate (__gnu_cxx::__verbose_terminate_handler);
#endif

    openlog("spamass-milter", LOG_PID, LOG_MAIL);


    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1) {
        switch (c) {
            case 'a':
                auth = true;
                break;
            case 'f':
                dofork = true;
                break;
            case 'g':
                group = strdup(optarg);
                break;
            case 'd':
                parse_debuglevel(optarg);
                break;
            case 'D':
                spamdhost = strdup(optarg);
                break;
            case 'e':
                flag_full_email = true;
                defaultdomain = strdup(optarg);
                break;
            case 'i':
                debug(D_MISC, "Parsing ignore list");
                parse_networklist(optarg, &ignorenets);
                break;
            case 'm':
                dontmodifyspam = true;
                smfilter.xxfi_flags &= ~SMFIF_CHGBODY;
                break;
            case 'M':
                dontmodify = true;
                dontmodifyspam = true;
                smfilter.xxfi_flags &= ~(SMFIF_CHGBODY|SMFIF_CHGHDRS);
                break;
            case 'p':
                sock = strdup(optarg);
                break;
            case 'P':
                pidfilename = strdup(optarg);
                break;
            case 'r':
                flag_reject = true;
                reject_score = atoi(optarg);
                break;
            case 'S':
                path_to_sendmail = strdup(optarg);
                break;
            case 'C':
                rejectcode = strdup (optarg);
                break;
            case 'R':
                rejecttext = strdup (optarg);
                break;
            case 'u':
                flag_sniffuser = true;
                defaultuser = strdup(optarg);
                break;
            case 'b':
            case 'B':
                if (flag_bucket)
                {
                    fprintf(stderr, "Can only have one -b or -B flag\n");
                    err = 1;
                    break;
                }
                flag_bucket = true;
                if (c == 'b')
                {
                    flag_bucket_only = true;
                    smfilter.xxfi_flags |= SMFIF_DELRCPT; // May delete recipients
                }
                // we will modify the recipient list; if spamc returns
                // indicating that this mail is spam, the message will be
                // sent to <optarg>@localhost
                smfilter.xxfi_flags |= SMFIF_ADDRCPT; // May add recipients
                // XXX we should probably verify that optarg is vaguely sane
                spambucket = strdup( optarg );
                break;
            case 'x':
                flag_expand = true;
                break;
            case 'T':
                debug(D_MISC, "Parsing recipient address ignore list");
                parse_addresslist(optarg, &ignoreaddrs);
                break;
            case '?':
                err = 1;
                break;
        }
    }

   if (flag_full_email && !flag_sniffuser)
   {
   	  fprintf(stderr, "-e flag requires -u\n");
      err=1;
   }

   /* remember the remainer of the arguments so we can pass them to spamc */
   spamc_argc = argc - optind;
   spamc_argv = argv + optind;

   if (!sock || err) {
      cout << PACKAGE_NAME << " - Version " << PACKAGE_VERSION << endl;
      cout << "SpamAssassin Sendmail Milter Plugin" << endl;
      cout << "Usage: spamass-milter -p socket [-b|-B bucket] [-d xx[,yy...]] [-D host]" << endl;
      cout << "                      [-e defaultdomain] [-f] [-i networks] [-m] [-M]" << endl;
      cout << "                      [-P pidfile] [-r nn] [-u defaultuser] [-x] [-a]" << endl;
      cout << "                      [-T addresses]" << endl;
      cout << "                      [-C rejectcode] [-R rejectmsg] [-g group]" << endl;
      cout << "                      [-- spamc args ]" << endl;
      cout << "   -p socket: path to create socket" << endl;
      cout << "   -b bucket: redirect spam to this mail address.  The orignal" << endl;
      cout << "          recipient(s) will not receive anything." << endl;
      cout << "   -B bucket: add this mail address as a BCC recipient of spam." << endl;
      cout << "   -C RejectCode: using this Reject Code." << endl;
      cout << "   -d xx[,yy ...]: set debug flags.  Logs to syslog" << endl;
      cout << "   -D host: connect to spamd at remote host (deprecated)" << endl;
      cout << "   -e defaultdomain: pass full email address to spamc instead of just\n"
              "          username.  Uses 'defaultdomain' if there was none" << endl;
      cout << "   -f: fork into background" << endl;
      cout << "   -g group: socket group (perms to 660 as well)" << endl;
      cout << "   -i: skip (ignore) checks from these IPs or netblocks" << endl;
      cout << "          example: -i 192.168.12.5,10.0.0.0/8,172.16.0.0/255.255.0.0" << endl;
      cout << "   -m: don't modify body, Content-type: or Subject:" << endl;
      cout << "   -M: don't modify the message at all" << endl;
      cout << "   -P pidfile: Put processid in pidfile" << endl;
      cout << "   -r nn: reject messages with a score >= nn with an SMTP error.\n"
              "          use -1 to reject any messages tagged by SA." << endl;
      cout << "   -R RejectText: using this Reject Text." << endl;
      cout << "   -u defaultuser: pass the recipient's username to spamc.\n"
              "          Uses 'defaultuser' if there are multiple recipients." << endl;
      cout << "   -x: pass email address through alias and virtusertable expansion." << endl;
      cout << "   -a: don't scan messages over an authenticated connection." << endl;
      cout << "   -T: skip (ignore) checks if any recipient is in this address list" << endl;
      cout << "          example: -T foo@bar.com,spamlover@yourdomain.com" << endl;
      cout << "   -- spamc args: pass the remaining flags to spamc." << endl;

      exit(EX_USAGE);
   }

    /* Set standard reject text */
    if (rejecttext == NULL) {
        rejecttext = strdup ("Blocked by SpamAssassin");
    }
    if (rejectcode == NULL) {
        rejectcode = strdup ("5.7.1");
    }

    if (pidfilename)
    {
        unlink(pidfilename);
        pidfile = fopen(pidfilename,"w");
        if (!pidfile)
        {
            fprintf(stderr, "Could not open pidfile: %s\n", strerror(errno));
            exit(1);
        }
        /* leave the file open through the fork, since we don't know our pid
           yet
        */
    }


    if (dofork == true)
    {
        if (daemon(0, 0) == -1)
        {
            fprintf(stderr, "daemon() failed: %s\n", strerror(errno));
            exit(1);
        }
    }

    if (pidfile)
    {
        fprintf(pidfile, "%ld\n", (long)getpid());
        fclose(pidfile);
        pidfile = NULL;
    }

   {
      struct stat junk;
      if (stat(sock,&junk) == 0) unlink(sock);
   }

   (void) smfi_setconn(sock);
	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	} else {
      debug(D_MISC, "smfi_register succeeded");
   }

	if (group)
	{
		struct group *gr;

		(void) smfi_opensocket(0);
		gr = getgrnam(group);
		if (gr)
		{
			int rc;
			rc = chown(sock, (uid_t)-1, gr->gr_gid);
			if (!rc)
			{
				(void) chmod(sock, 0660);
			} else {
				perror("group option, chown");
				exit(EX_NOPERM);
			}
		} else {
			perror("group option, getgrnam");
			exit(EX_NOUSER);
		}
	}

	debug(D_ALWAYS, "spamass-milter %s starting", PACKAGE_VERSION);
	err = smfi_main();
	debug(D_ALWAYS, "spamass-milter %s exiting", PACKAGE_VERSION);
	if (pidfilename)
		unlink(pidfilename);
	return err;
}

// }}}

/* Update a header if SA changes it, or add it if it is new. */
void update_or_insert(SpamAssassin* assassin, SMFICTX* ctx, string oldstring, t_setter setter, const char *header )
{
	string::size_type eoh1 = assassin->d().find("\n\n");
	string::size_type eoh2 = assassin->d().find("\n\r\n");
	string::size_type eoh = ( eoh1 < eoh2 ? eoh1 : eoh2 );

	string newstring;
	string::size_type oldsize;

	debug(D_UORI, "u_or_i: looking at <%s>", header);
	debug(D_UORI, "u_or_i: oldstring: <%s>", oldstring.c_str());

	newstring = retrieve_field(assassin->d().substr(0, eoh), header);
	debug(D_UORI, "u_or_i: newstring: <%s>", newstring.c_str());

	oldsize = callsetter(*assassin,setter)(newstring);

	if (!dontmodify)
	{
		if (newstring != oldstring)
		{
			/* change if old one was present, append if non-null */
			char* cstr = const_cast<char*>(newstring.c_str());
			if (oldsize > 0)
			{
				debug(D_UORI, "u_or_i: changing");
				smfi_chgheader(ctx, const_cast<char*>(header), 1, newstring.size() > 0 ?
					cstr : NULL );
			} else if (newstring.size() > 0)
			{
				debug(D_UORI, "u_or_i: inserting");
				smfi_addheader(ctx, const_cast<char*>(header), cstr);
			}
		} else
		{
			debug(D_UORI, "u_or_i: no change");
		}
	}
}

// {{{ Assassinate

//
// implement the changes suggested by SpamAssassin for the mail.  Returns
// the milter error code.
int
assassinate(SMFICTX* ctx, SpamAssassin* assassin)
{
  // find end of header (eol in last line of header)
  // and beginning of body
  string::size_type eoh1 = assassin->d().find("\n\n");
  string::size_type eoh2 = assassin->d().find("\n\r\n");
  string::size_type eoh = (eoh1 < eoh2) ? eoh1 : eoh2;
  string::size_type bob = assassin->d().find_first_not_of("\r\n", eoh);

  if (bob == string::npos)
  	bob = assassin->d().size();

  update_or_insert(assassin, ctx, assassin->spam_flag(), &SpamAssassin::set_spam_flag, "X-Spam-Flag");
  update_or_insert(assassin, ctx, assassin->spam_status(), &SpamAssassin::set_spam_status, "X-Spam-Status");

  /* Summarily reject the message if SA tagged it, or if we have a minimum
     score, reject if it exceeds that score. */
  if (flag_reject)
  {
	bool do_reject = false;
	if (reject_score == -1 && !assassin->spam_flag().empty())
		do_reject = true;
	if (reject_score != -1)
	{
		int score, rv;
		const char *spam_status = assassin->spam_status().c_str();
		/* SA 3.0 uses the keyword "score" */
		rv = sscanf(spam_status,"%*s score=%d", &score);
		if (rv != 1)
		{
			/* SA 2.x uses the keyword "hits" */
			rv = sscanf(spam_status,"%*s hits=%d", &score);
		}
		if (rv != 1)
			debug(D_ALWAYS, "Could not extract score from <%s>", spam_status);
		else
		{
			debug(D_MISC, "SA score: %d", score);
			if (score >= reject_score)
				do_reject = true;
		}
	}
	if (do_reject)
	{
		debug(D_MISC, "Rejecting");
		smfi_setreply(ctx, const_cast<char*>("550"), rejectcode, rejecttext);


		if (flag_bucket)
		{
			/* If we also want a copy of the spam, shell out to sendmail and
			   send another copy.  The milter API will not let you send the
			   message AND return a failure code to the sender, so this is
			   the only way to do it. */
			char *popen_argv[3];
			FILE *p;
			pid_t pid;

			popen_argv[0] = path_to_sendmail;
			popen_argv[1] = spambucket;
			popen_argv[2] = NULL;

			debug(D_COPY, "calling %s %s", path_to_sendmail, spambucket);
			p = popenv(popen_argv, "w", &pid);
			if (!p)
			{
				debug(D_COPY, "popenv failed(%s).  Will not send a copy to spambucket", strerror(errno));
			} else
			{
				// Send message provided by SpamAssassin
				fwrite(assassin->d().c_str(), assassin->d().size(), 1, p);
				fclose(p); p = NULL;
				waitpid(pid, NULL, 0);
			}
		}
		return SMFIS_REJECT;
	}
  }

  /* Drop the message into the spam bucket if it's spam */
  if ( flag_bucket ) {
        if (!assassin->spam_flag().empty()) {
          // first, add the spambucket address
          if ( smfi_addrcpt( ctx, spambucket ) != MI_SUCCESS ) {
                throw string( "Failed to add spambucket to recipients" );
          }
          if (flag_bucket_only) {
                // Move recipients to a non-active header, one at a
                // time. Note, this may generate multiple X-Spam-Orig-To
                // headers, but that's okay.
                while( !assassin->recipients.empty()) {
                  if ( smfi_addheader( ctx, const_cast<char *>("X-Spam-Orig-To"), (char *)assassin->recipients.front().c_str()) != MI_SUCCESS ) {
                        throw string( "Failed to save recipient" );
                  }

                  // It's not 100% important that this succeeds, so we'll just warn on failure rather than bailing out.
                  if ( smfi_delrcpt( ctx, (char *)assassin->recipients.front().c_str()) != MI_SUCCESS ) {
                        // throw_error really just logs a warning as opposed to actually throw()ing
                        debug(D_ALWAYS, "Failed to remove recipient %s from the envelope", assassin->recipients.front().c_str() );
                  }
                  assassin->recipients.pop_front();
                }
          }
        }
  }

  update_or_insert(assassin, ctx, assassin->spam_report(), &SpamAssassin::set_spam_report, "X-Spam-Report");
  update_or_insert(assassin, ctx, assassin->spam_prev_content_type(), &SpamAssassin::set_spam_prev_content_type, "X-Spam-Prev-Content-Type");
  update_or_insert(assassin, ctx, assassin->spam_level(), &SpamAssassin::set_spam_level, "X-Spam-Level");
  update_or_insert(assassin, ctx, assassin->spam_checker_version(), &SpamAssassin::set_spam_checker_version, "X-Spam-Checker-Version");

  //
  // If SpamAssassin thinks it is spam, replace
  //  Subject:
  //  Content-Type:
  //  <Body>
  //
  //  However, only issue the header replacement calls if the content has
  //  actually changed. If SA didn't change subject or content-type, don't
  //  replace here unnecessarily.
  if (!dontmodifyspam && assassin->spam_flag().size()>0)
    {
	  update_or_insert(assassin, ctx, assassin->subject(), &SpamAssassin::set_subject, "Subject");
	  update_or_insert(assassin, ctx, assassin->content_type(), &SpamAssassin::set_content_type, "Content-Type");

      // Replace body with the one SpamAssassin provided
      string::size_type body_size = assassin->d().size() - bob;
      string body=assassin->d().substr(bob, string::npos);
      if ( smfi_replacebody(ctx, (unsigned char *)body.c_str(), body_size) == MI_FAILURE )
	throw string("error. could not replace body.");

    }

  return SMFIS_CONTINUE;
}

// retrieve the content of a specific field in the header
// and return it.
string
retrieve_field(const string& header, const string& field)
{
  // Find the field
  string::size_type field_start = string::npos;
  string::size_type field_end = string::npos;
  string::size_type idx = 0;

  while( field_start == string::npos ) {
	idx = find_nocase( header, field + ":", idx );

	// no match
	if ( idx == string::npos ) {
	  return string( "" );
	}

	// The string we've found needs to be either at the start of the
	// headers string, or immediately following a "\n"
	if ( idx != 0 ) {
	  if ( header[ idx - 1 ] != '\n' ) {
		idx++; // so we don't get stuck in an infinite loop
		continue; // loop around again
	  }
	}

	field_start = idx;
  }

  // A mail field starts just after the header. Ideally, there's a
  // space, but it's possible that there isn't.
  field_start += field.length() + 1;
  if ( field_start < ( header.length() - 1 ) && header[ field_start ] == ' ' ) {
	field_start++;
  }

  // See if there's anything left, to shortcut the rest of the
  // function.
  if ( field_start == header.length() - 1 ) {
	return string( "" );
  }

  // The field continues to the end of line. If the start of the next
  // line is whitespace, then the field continues.
  idx = field_start;
  while( field_end == string::npos ) {
	idx = header.find( "\n", idx );

	// if we don't find a "\n", gobble everything to the end of the headers
	if ( idx == string::npos ) {
	  field_end = header.length();
	} else {
	  // check the next character
	  if (( idx + 1 ) < header.length() && ( isspace( header[ idx + 1 ] ))) {
		idx ++; // whitespace found, so wrap to the next line
	  } else {
		field_end = idx;
	  }
	}
  }

  /* if the header line ends in \r\n, don't return the \r */
  if (header[field_end-1] == '\r')
  	field_end--;

  string data = header.substr( field_start, field_end - field_start );

  /* Replace all CRLF pairs with LF */
  idx = 0;
  while ( (idx = data.find("\r\n", idx)) != string::npos )
  {
  	data.replace(idx,2,"\n");
  }

  return data;
}


// }}}

// {{{ MLFI callbacks

//
// Gets called once when a client connects to sendmail
//
// gets the originating IP address and checks it against the ignore list
// if it isn't in the list, store the IP in a structure and store a
// pointer to it in the private data area.
//
sfsistat
mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
	struct context *sctx;
	const char *macro_j, *macro__;
	int rv;

	debug(D_FUNC, "mlfi_connect: enter");

	/* allocate a structure to store the IP address (and SA object) in */
	sctx = (struct context *)malloc(sizeof(*sctx));
	if (!hostaddr)
	{
		static struct sockaddr_in localhost;

		/* not a socket; probably a local user calling sendmail directly */
		/* set to 127.0.0.1 */
		strcpy(sctx->connect_ip, "127.0.0.1");
		localhost.sin_family = AF_INET;
		localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		hostaddr = (struct sockaddr*) &localhost;
	} else
	{
		getnameinfo(hostaddr, sizeof(struct sockaddr_in6),
		            sctx->connect_ip, 63, NULL, 0, NI_NUMERICHOST);
		debug(D_FUNC, "Remote address: %s", sctx->connect_ip);
	}
	sctx->assassin = NULL;
	sctx->helo = NULL;
	sctx->our_fqdn = NULL;
	sctx->sender_address = NULL;
	sctx->queueid = NULL;
	sctx->auth_authen = NULL;
	sctx->auth_ssf = NULL;

	/* store our FQDN */
	macro_j = smfi_getsymval(ctx, const_cast<char *>("j"));
	if (!macro_j)
	{
		macro_j = "localhost";
		warnmacro("j", "CONNECT");
	}
	sctx->our_fqdn = strdup(macro_j);

	/* store the validated sending site's address */
	macro__ = smfi_getsymval(ctx, const_cast<char *>("_"));
	if (!macro__)
	{
		macro__ = "unknown";
		warnmacro("_", "CONNECT");
	}
	sctx->sender_address = strdup(macro__);

	/* store a pointer to our private data with setpriv */
	rv = smfi_setpriv(ctx, sctx);
	if (rv != MI_SUCCESS)
	{
		debug(D_ALWAYS, "smfi_setpriv failed!");
		return SMFIS_TEMPFAIL;
	}
	/* debug(D_ALWAYS, "ZZZ set private context to %p", sctx); */

	//debug(D_FUNC, "sctx->connect_ip: `%d'", sctx->connect_ip.sin_family);

	if (ip_in_networklist(hostaddr, &ignorenets))
	{
		debug(D_NET, "%s is in our ignore list - accepting message",
		      sctx->connect_ip);
		debug(D_FUNC, "mlfi_connect: exit ignore");
		return SMFIS_ACCEPT;
	}

	// Tell Milter to continue
	debug(D_FUNC, "mlfi_connect: exit");

	return SMFIS_CONTINUE;
}

//
// Gets called on every "HELO"
//
// stores the result in the context structure
//
sfsistat mlfi_helo(SMFICTX * ctx, char * helohost)
{
	struct context *sctx = (struct context*)smfi_getpriv(ctx);
	if (sctx->helo)
		free(sctx->helo);
	sctx->helo = strdup(helohost);

	return SMFIS_CONTINUE;
}

//
// Gets called first for all messages
//
// creates SpamAssassin object and makes pointer to it
// private data of this filter process
//
sfsistat
mlfi_envfrom(SMFICTX* ctx, char** envfrom)
{
  SpamAssassin* assassin;
  struct context *sctx = (struct context *)smfi_getpriv(ctx);
  const char *queueid, *macro_auth_ssf, *macro_auth_authen;

  if (sctx == NULL)
  {
    debug(D_ALWAYS, "smfi_getpriv failed!");
    return SMFIS_TEMPFAIL;
  }
  /* debug(D_ALWAYS, "ZZZ got private context %p", sctx); */

  if (auth) {
    const char *auth_type = smfi_getsymval(ctx,
        const_cast<char *>("{auth_type}"));

    if (auth_type) {
      debug(D_MISC, "auth_type=%s", auth_type);
      return SMFIS_ACCEPT;
    }
  }

  debug(D_FUNC, "mlfi_envfrom: enter");
  try {
    // launch new SpamAssassin
    assassin=new SpamAssassin;
  } catch (string& problem)
    {
      throw_error(problem);
      return SMFIS_TEMPFAIL;
    };

  assassin->set_connectip(string(sctx->connect_ip));

  // Store a pointer to the assassin object in our context struct
  sctx->assassin = assassin;

  // remember the MAIL FROM address
  assassin->set_from(string(envfrom[0]));

  // remember the queueid for this message
  queueid=smfi_getsymval(ctx, const_cast<char *>("i"));
  if (!queueid)
  {
    queueid="unknown";
    warnmacro("i", "ENVFROM");
  }
  sctx->queueid = strdup(queueid);
  debug(D_MISC, "queueid=%s", queueid);

  // remember the SMTP AUTH login name
  macro_auth_authen = smfi_getsymval(ctx, const_cast<char *>("{auth_authen}"));
  if (!macro_auth_authen)
  {
    macro_auth_authen = "";
    // Don't issue a warning for the auth_authen macro as
    // it is likely to be unset much of the time - it's
    // only set if the client has authenticated.
    //
    // Similarly, we only issue warnings for the other
    // auth-related macros if {auth_authen) is available.
    //
    // warnmacro("auth_authen", "ENVFROM");
  }
  sctx->auth_authen = strdup(macro_auth_authen);

  // remember the SASL cipher bits
  macro_auth_ssf = smfi_getsymval(ctx, const_cast<char *>("{auth_ssf}"));
  if (!macro_auth_ssf)
  {
    macro_auth_ssf = "";
    if (strlen(macro_auth_authen)) {
      warnmacro("auth_ssf", "ENVFROM");
    }
  }
  sctx->auth_ssf = strdup(macro_auth_ssf);

  // tell Milter to continue
  debug(D_FUNC, "mlfi_envfrom: exit");

  return SMFIS_CONTINUE;
}

//
// Gets called once for each recipient
//
// stores the first recipient in the spamassassin object and
// stores all addresses and the number thereof (some redundancy)
//


sfsistat
mlfi_envrcpt(SMFICTX* ctx, char** envrcpt)
{
	struct context *sctx = (struct context*)smfi_getpriv(ctx);
	SpamAssassin* assassin = sctx->assassin;
	FILE *p;

	debug(D_FUNC, "mlfi_envrcpt: enter");

   if (addr_in_addresslist(envrcpt[0], &ignoreaddrs))
   {
      debug(D_RCPT, "%s is in our ignore addrlist - accepting message", envrcpt[0]);
      debug(D_FUNC, "mlfi_envrcpt: exit ignore");
      return SMFIS_ACCEPT;
   }

	if (flag_expand)
	{
		/* open a pipe to sendmail so we can do address expansion */

		char buf[1024];
		char *popen_argv[4];
		pid_t pid;

		popen_argv[0] = path_to_sendmail;
		popen_argv[1] = (char *)"-bv";
		popen_argv[2] = envrcpt[0];
		popen_argv[3] = NULL;

		debug(D_RCPT, "calling %s -bv %s", path_to_sendmail, envrcpt[0]);

		p = popenv(popen_argv, "r", &pid);
		if (!p)
		{
			debug(D_RCPT, "popenv failed(%s).  Will not expand aliases", strerror(errno));
			assassin->expandedrcpt.push_back(envrcpt[0]);
		} else
		{
			while (fgets(buf, sizeof(buf), p) != NULL)
			{
				int i = strlen(buf);
				/* strip trailing EOLs */
				while (i > 0 && buf[i - 1] <= ' ')
					i--;
				buf[i] = '\0';
				debug(D_RCPT, "sendmail output: %s", buf);
				/*	From a quick scan of the sendmail source, a valid email
					address gets printed via either
					    "deliverable: mailer %s, host %s, user %s"
					or  "deliverable: mailer %s, user %s"
				*/
				if (strstr(buf, "... deliverable: mailer "))
				{
					char *p=strstr(buf,", user ");
					/* anything after ", user " is the email address */
					debug(D_RCPT, "user: %s", p+7);
					assassin->expandedrcpt.push_back(p+7);
				}
			}
			fclose(p); p = NULL;
			waitpid(pid, NULL, 0);
		}
	} else
	{
		assassin->expandedrcpt.push_back(envrcpt[0]);
	}
	debug(D_RCPT, "Total of %d actual recipients", (int)assassin->expandedrcpt.size());

	if (assassin->numrcpt() == 0)
	{
		/* Send the envelope headers as X-Envelope-From: and
		   X-Envelope-To: so that SpamAssassin can use them in its
		   whitelist checks.  Also forge as complete a dummy
		   Received: header as possible because SA gets a lot of
		   info from it.

			HReceived: $?sfrom $s $.$?_($?s$|from $.$_)
				$.$?{auth_type}(authenticated$?{auth_ssf} bits=${auth_ssf}$.)
				$.by $j ($v/$Z)$?r with $r$. id $i$?{tls_version}
				(version=${tls_version} cipher=${cipher} bits=${cipher_bits} verify=${verify})$.$?u
				for $u; $|;
				$.$b$?g
				(envelope-from $g)$.

		*/
		const char *macro_b, *macro_i, *macro_j, *macro_r,
		           *macro_s, *macro_v, *macro_Z, *macro__,
			   *macro_auth_ssf, *macro_auth_authen;
		char date[32];

		/* RFC 822 date. */
		macro_b = smfi_getsymval(ctx, const_cast<char *>("b"));
		if (!macro_b)
		{
			time_t tval;
			time(&tval);
			strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime(&tval));
			macro_b = date;
			warnmacro("b", "ENVRCPT");
		}

		/* queue ID */
		macro_i = sctx->queueid;

		/* FQDN */
		macro_j = sctx->our_fqdn;

		/* Sender address */
		macro__ = sctx->sender_address;

		/* Protocol used to receive the message */
		macro_r = smfi_getsymval(ctx, const_cast<char *>("r"));
		if (!macro_r)
		{
			macro_r = "SMTP";
			warnmacro("r", "ENVRCPT");
		}

		/* SMTP AUTH details */
		macro_auth_authen = sctx->auth_authen;
		macro_auth_ssf = sctx->auth_ssf;

		/* Sendmail currently cannot pass us the {s} macro, but
		   I do not know why.  Leave this in for the day sendmail is
		   fixed.  Until that day, use the value remembered by
		   mlfi_helo()
		*/
		macro_s = smfi_getsymval(ctx, const_cast<char *>("s"));
		if (!macro_s)
			macro_s = sctx->helo;
		if (!macro_s)
			macro_s = "nohelo";

		/* Sendmail binary version */
		macro_v = smfi_getsymval(ctx, const_cast<char *>("v"));
		if (!macro_v)
		{
			macro_v = "8.13.0";
			warnmacro("v", "ENVRCPT");
		}

		/* Sendmail .cf version */
		macro_Z = smfi_getsymval(ctx, const_cast<char *>("Z"));
		if (!macro_Z)
		{
			macro_Z = "8.13.0";
			warnmacro("Z", "ENVRCPT");
		}

		assassin->output((string)"X-Envelope-From: "+assassin->from()+"\r\n");
		assassin->output((string)"X-Envelope-To: "+envrcpt[0]+"\r\n");

		string rec_header;

		rec_header = (string) "Received: from " + macro_s + " (" + macro__ + ")\r\n\t";

		if (strlen(macro_auth_authen))
		{
			rec_header += (string) "(authenticated";
			if (strlen(macro_auth_ssf))
			{
				rec_header += (string) " bits=" + macro_auth_ssf;
			}
			rec_header += (string) ")\r\n\t";
		}

		rec_header += (string) "by " + macro_j + " (" + macro_v + "/" + macro_Z + ") with " +
			macro_r + " id " + macro_i + ";\r\n\t" +
			macro_b + "\r\n\t" +
			"(envelope-from " + assassin->from() + ")\r\n";

		debug(D_SPAMC, "Received header for spamc: %s", rec_header.c_str());
		assassin->output(rec_header);

	} else
		assassin->output((string)"X-Envelope-To: "+envrcpt[0]+"\r\n");

	/* increment RCPT TO: count */
	assassin->set_numrcpt();

	/* If we expanded to at least one user and we haven't recorded one yet,
	   record the first one */
	if (!assassin->expandedrcpt.empty() && (assassin->rcpt().size() == 0))
	{
		debug(D_RCPT, "remembering %s for spamc", assassin->expandedrcpt.front().c_str());
		assassin->set_rcpt(assassin->expandedrcpt.front());
	}

	debug(D_RCPT, "remembering recipient %s", envrcpt[0]);
	assassin->recipients.push_back( envrcpt[0] ); // XXX verify that this worked

	debug(D_FUNC, "mlfi_envrcpt: exit");

	return SMFIS_CONTINUE;
}

//
// Gets called repeatedly for all header fields
//
// assembles the headers and passes them on to the SpamAssassin client
// through the pipe.
//
// only exception: SpamAssassin header fields (X-Spam-*) get suppressed
// but are being stored in the SpamAssassin element.
//
// this function also starts the connection with the SPAMC program the
// first time it is called.
//

sfsistat
mlfi_header(SMFICTX* ctx, char* headerf, char* headerv)
{
  SpamAssassin* assassin = ((struct context *)smfi_getpriv(ctx))->assassin;
  debug(D_FUNC, "mlfi_header: enter");

  // Check if the SPAMC program has already been run, if not we run it.
  if ( !(assassin->connected) )
     {
       try {
         assassin->connected = 1; // SPAMC is getting ready to run
         assassin->Connect();
       }
       catch (string& problem) {
         throw_error(problem);
         ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
         delete assassin;
         debug(D_FUNC, "mlfi_header: exit error connect");
         return SMFIS_TEMPFAIL;
       };
     }

  // Is it a "X-Spam-" header field?
  if ( cmp_nocase_partial("X-Spam-", headerf) == 0 )
    {
      int suppress = 1;
      // memorize content of old fields

      if ( cmp_nocase_partial("X-Spam-Status", headerf) == 0 )
	assassin->set_spam_status(headerv);
      else if ( cmp_nocase_partial("X-Spam-Flag", headerf) == 0 )
	assassin->set_spam_flag(headerv);
      else if ( cmp_nocase_partial("X-Spam-Report", headerf) == 0 )
	assassin->set_spam_report(headerv);
      else if ( cmp_nocase_partial("X-Spam-Prev-Content-Type", headerf) == 0 )
	assassin->set_spam_prev_content_type(headerv);
      else if ( cmp_nocase_partial("X-Spam-Level", headerf) == 0 )
	assassin->set_spam_level(headerv);
      else if ( cmp_nocase_partial("X-Spam-Checker-Version", headerf) == 0 )
	assassin->set_spam_checker_version(headerv);
      else
      {
      	/* Hm. X-Spam header, but not one we recognize.  Pass it through. */
      	suppress = 0;
      }

      if (suppress)
      {
	debug(D_FUNC, "mlfi_header: suppress");
	return SMFIS_CONTINUE;
      }
    }

  // Content-Type: will be stored if present
  if ( cmp_nocase_partial("Content-Type", headerf) == 0 )
    assassin->set_content_type(headerv);

  // Subject: should be stored
  if ( cmp_nocase_partial("Subject", headerf) == 0 )
    assassin->set_subject(headerv);

  // assemble header to be written to SpamAssassin
  string header = string(headerf) + ": " + headerv + "\r\n";

  try {
    // write to SpamAssassin client
    assassin->output(header.c_str(),header.size());
  } catch (string& problem)
    {
      throw_error(problem);
      ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
      delete assassin;
      debug(D_FUNC, "mlfi_header: exit error output");
      return SMFIS_TEMPFAIL;
    };

  // go on...
  debug(D_FUNC, "mlfi_header: exit");

  return SMFIS_CONTINUE;
}

//
// Gets called once when the header is finished.
//
// writes empty line to SpamAssassin client to separate
// headers from body.
//
sfsistat
mlfi_eoh(SMFICTX* ctx)
{
  SpamAssassin* assassin = ((struct context *)smfi_getpriv(ctx))->assassin;

  debug(D_FUNC, "mlfi_eoh: enter");

  // Check if the SPAMC program has already been run, if not we run it.
  if ( !(assassin->connected) )
     {
       try {
         assassin->connected = 1; // SPAMC is getting ready to run
         assassin->Connect();
       }
       catch (string& problem) {
         throw_error(problem);
         ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
         delete assassin;

         debug(D_FUNC, "mlfi_eoh: exit error connect");
         return SMFIS_TEMPFAIL;
       };
     }

  try {
    // add blank line between header and body
    assassin->output("\r\n",2);
  } catch (string& problem)
    {
      throw_error(problem);
      ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
      delete assassin;

      debug(D_FUNC, "mlfi_eoh: exit error output");
      return SMFIS_TEMPFAIL;
    };

  // go on...

  debug(D_FUNC, "mlfi_eoh: exit");
  return SMFIS_CONTINUE;
}

//
// Gets called repeatedly to transmit the body
//
// writes everything directly to SpamAssassin client
//
sfsistat
mlfi_body(SMFICTX* ctx, u_char *bodyp, size_t bodylen)
{
  debug(D_FUNC, "mlfi_body: enter");
  SpamAssassin* assassin = ((struct context *)smfi_getpriv(ctx))->assassin;


  try {
    assassin->output(bodyp, bodylen);
  } catch (string& problem)
    {
      throw_error(problem);
      ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
      delete assassin;
      debug(D_FUNC, "mlfi_body: exit error");
      return SMFIS_TEMPFAIL;
    };

  // go on...
  debug(D_FUNC, "mlfi_body: exit");
  return SMFIS_CONTINUE;
}

//
// Gets called once at the end of mail processing
//
// tells SpamAssassin client that the mail is complete
// through EOF and then modifies the mail accordingly by
// calling the "assassinate" function
//
sfsistat
mlfi_eom(SMFICTX* ctx)
{
  SpamAssassin* assassin = ((struct context *)smfi_getpriv(ctx))->assassin;
  int milter_status;

  debug(D_FUNC, "mlfi_eom: enter");
  try {

    // close output pipe to signal EOF to SpamAssassin
    assassin->close_output();

    // read what the Assassin is telling us
    assassin->input();

    milter_status = assassinate(ctx, assassin);

    // now cleanup the element.
    ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
    delete assassin;

  } catch (string& problem)
    {
      throw_error(problem);
      ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
      delete assassin;
      debug(D_FUNC, "mlfi_eom: exit error");
      return SMFIS_TEMPFAIL;
    };

  // go on...
  debug(D_FUNC, "mlfi_eom: exit");
  return milter_status;
}

//
// Gets called on session-basis. This keeps things nice & quiet.
//
sfsistat
mlfi_close(SMFICTX* ctx)
{
  struct context *sctx;
  debug(D_FUNC, "mlfi_close");

  sctx = (struct context*)smfi_getpriv(ctx);
  if (sctx == NULL)
    return SMFIS_ACCEPT;

  if (sctx->helo)
  	free(sctx->helo);
  if (sctx->our_fqdn)
 	free(sctx->our_fqdn);
  if (sctx->sender_address)
 	free(sctx->sender_address);
  if (sctx->queueid)
 	free(sctx->queueid);
  if (sctx->auth_authen)
 	free(sctx->auth_authen);
  if (sctx->auth_ssf)
 	free(sctx->auth_ssf);

  free(sctx);
  smfi_setpriv(ctx, NULL);

  return SMFIS_ACCEPT;
}

//
// Gets called when things are being aborted.
//
// kills the SpamAssassin object, its destructor should
// take care of everything.
//
sfsistat
mlfi_abort(SMFICTX* ctx)
{
  SpamAssassin* assassin = ((struct context *)smfi_getpriv(ctx))->assassin;

  debug(D_FUNC, "mlfi_abort");
  ((struct context *)smfi_getpriv(ctx))->assassin=NULL;
  delete assassin;

  return SMFIS_ACCEPT;
}

// }}}

// {{{ SpamAssassin Class

//
// This is a new constructor for the SpamAssassin object.  It simply
// initializes two variables.  The original constructor has been
// renamed to Connect().
//
SpamAssassin::SpamAssassin():
  error(false),
  running(false),
  connected(false),
  _numrcpt(0)
{
}


SpamAssassin::~SpamAssassin()
{
	if (connected)
	{
		// close all pipes that are still open
		if (pipe_io[0][0] > -1)	close(pipe_io[0][0]);
		if (pipe_io[0][1] > -1)	close(pipe_io[0][1]);
		if (pipe_io[1][0] > -1)	close(pipe_io[1][0]);
		if (pipe_io[1][1] > -1)	close(pipe_io[1][1]);

		// child still running?
		if (running)
		{
			// make sure the pid is valid
			if (pid > 0) {
				// slaughter child
				kill(pid, SIGKILL);

				// wait for child to terminate
				int status;
				waitpid(pid, &status, 0);
			}
		}
    }

	// Clean up the recip list. Might be overkill, but it's good housekeeping.
	while( !recipients.empty())
	{
		recipients.pop_front();
	}
	// Clean up the recip list. Might be overkill, but it's good housekeeping.
	while( !expandedrcpt.empty())
	{
		expandedrcpt.pop_front();
	}
}

//
// This is the old SpamAssassin constructor.  It has been renamed Connect(),
// and is now called at the beginning of the mlfi_header() function.
//

void SpamAssassin::Connect()
{
  // set up pipes for in- and output
  if (pipe(pipe_io[0]))
    throw string(string("pipe error: ")+string(strerror(errno)));
  if (pipe(pipe_io[1]))
    throw string(string("pipe error: ")+string(strerror(errno)));

  // now execute SpamAssassin client for contact with SpamAssassin spamd

  // start child process
  switch(pid = fork())
    {
    case -1:
      // forking trouble. throw error.
      throw string(string("fork error: ")+string(strerror(errno)));
      break;
    case 0:
      // +++ CHILD +++

      // close unused pipes
      close(pipe_io[1][0]);
      close(pipe_io[0][1]);

      // redirect stdin(0), stdout(1) and stderr(2)
      dup2(pipe_io[0][0],0);
      dup2(pipe_io[1][1],1);
      dup2(pipe_io[1][1],2);

      closeall(3);

      // execute spamc
      // absolute path (determined in autoconf)
      // should be a little more secure
      // XXX arbitrary 100-argument max
      int argc = 0;
      char** argv = (char**) malloc(100*sizeof(char*));
      argv[argc++] = strdup(SPAMC);
      if (flag_sniffuser)
      {
        argv[argc++] = strdup("-u");
        if ( expandedrcpt.size() != 1 )
        {
          // More (or less?) than one recipient, so we pass the default
          // username to SPAMC.  This way special rules can be defined for
          // multi recipient messages.
          debug(D_RCPT, "%d recipients; spamc gets default username %s", (int)expandedrcpt.size(), defaultuser);
          argv[argc++] = defaultuser;
        } else
        {
          // There is only 1 recipient so we pass the username
          // (converted to lowercase) to SPAMC.  Don't worry about
          // freeing this memory as we're exec()ing anyhow.
          if (flag_full_email)
            argv[argc] = strlwr(strdup(full_user().c_str()));
          else
            argv[argc] = strlwr(strdup(local_user().c_str()));

          debug(D_RCPT, "spamc gets %s", argv[argc]);

          argc++;
        }
      }
      if (spamdhost)
      {
        argv[argc++] = strdup("-d");
        argv[argc++] = spamdhost;
      }
      if (spamc_argc)
      {
      	memcpy(argv+argc, spamc_argv, spamc_argc * sizeof(char *));
      	argc += spamc_argc;
      }
      argv[argc++] = 0;

      execvp(argv[0] , argv); // does not return!

      // execution failed
      throw_error(string("execution error: ")+string(strerror(errno)));
      _exit(1);
      break;
    }

  // +++ PARENT +++

  // close unused pipes
  close(pipe_io[0][0]);
  close(pipe_io[1][1]);
  pipe_io[0][0]=-1;
  pipe_io[1][1]=-1;

  // mark the pipes non-blocking
  if(fcntl(pipe_io[0][1], F_SETFL, O_NONBLOCK) == -1)
     throw string(string("Cannot set pipe01 nonblocking: ")+string(strerror(errno)));
#if 0  /* don't really need to make the sink pipe nonblocking */
  if(fcntl(pipe_io[1][0], F_SETFL, O_NONBLOCK) == -1)
     throw string(string("Cannot set pipe10 nonblocking: ")+string(strerror(errno)));
#endif

  // we have to assume the client is running now.
  running=true;

  /* If we have any buffered output, write it now. */
  if (outputbuffer.size())
  {
    output(outputbuffer);
    outputbuffer="";
  }
}

// write to SpamAssassin
void
SpamAssassin::output(const void* buffer, long size)
{
  debug(D_FUNC, "::output enter");

  debug(D_SPAMC, "output \"%*.*s\"", (int)size, (int)size, (char *)buffer);

  // if there are problems, fail.
  if (error)
    throw string("tried output despite problems. failed.");

  /* If we haven't launched spamc yet, just store the data */
  if (!connected)
  {
	/* Silly C++ can't tell the difference between
		(const char*, string::size_type) and
		(string::size_type, char), so we have to cast the parameters.
	*/
  	outputbuffer.append((const char *)buffer,(string::size_type)size);
  	debug(D_FUNC, "::output exit1");
  	return;
  }

  // send to SpamAssassin
  long total = 0;
  long wsize = 0;
  string reason;
  int status;
  do {
	struct pollfd fds[2];
	int nfds = 2, nready;
	fds[0].fd = pipe_io[0][1];
	fds[0].events = POLLOUT;
	fds[1].fd = pipe_io[1][0];
	fds[1].events = POLLIN;

	debug(D_POLL, "polling fds %d and %d", pipe_io[0][1], pipe_io[1][0]);
	nready = poll(fds, nfds, 1000);
	if (nready == -1)
		throw("poll failed");

	debug(D_POLL, "poll returned %d, fd0=%d, fd1=%d", nready, fds[0].revents, fds[1].revents);

	if (fds[1].revents & (POLLERR|POLLNVAL|POLLHUP))
	{
		throw string("poll says my read pipe is busted");
	}

	if (fds[0].revents & (POLLERR|POLLNVAL|POLLHUP))
	{
		throw string("poll says my write pipe is busted");
	}

	if (fds[1].revents & POLLIN)
	{
		debug(D_POLL, "poll says I can read");
		read_pipe();
	}

	if (fds[0].revents & POLLOUT)
	{
		debug(D_POLL, "poll says I can write");
		switch(wsize = write(pipe_io[0][1], (char *)buffer + total, size - total))
		{
		  case -1:
			if (errno == EAGAIN)
				continue;
			reason = string(strerror(errno));

			// close the pipes
			close(pipe_io[0][1]);
			close(pipe_io[1][0]);
			pipe_io[0][1]=-1;
			pipe_io[1][0]=-1;

			// Slaughter child
			kill(pid, SIGKILL);

			// set flags
			error = true;
			running = false;

			// wait until child is dead
			waitpid(pid, &status, 0);

			throw string(string("write error: ")+reason);
			break;
	      default:
			total += wsize;
			debug(D_POLL, "wrote %ld bytes", wsize);
			break;
		}
	}
  } while ( total < size );

  debug(D_FUNC, "::output exit2");
}

void SpamAssassin::output(const void* buffer)
{
	output(buffer, strlen((const char *)buffer));
}

void SpamAssassin::output(string buffer)
{
	output(buffer.c_str(), buffer.size());
}

// close output pipe
void
SpamAssassin::close_output()
{
  if(close(pipe_io[0][1]))
    throw string(string("close error: ")+string(strerror(errno)));
  pipe_io[0][1]=-1;
}

void
SpamAssassin::input()
{
  debug(D_FUNC, "::input enter");
  // if the child has exited or we experienced an error, return
  // immediately.
  if (!running || error)
  {
    debug(D_FUNC, "::input exit1");
    return;
  }

  // keep reading from input pipe until it is empty
  empty_and_close_pipe();

  // that's it, we're through
  running = false;

  // wait until child is dead
  int status;
  if(waitpid(pid, &status, 0)<0)
    {
      error = true;
      throw string(string("waitpid error: ")+string(strerror(errno)));
    };
	debug(D_FUNC, "::input exit2");
}

//
// return reference to mail
//
string&
SpamAssassin::d()
{
  return mail;
}

//
// get values of the different SpamAssassin fields
//
string&
SpamAssassin::spam_status()
{
  return x_spam_status;
}

string&
SpamAssassin::spam_flag()
{
  return x_spam_flag;
}

string&
SpamAssassin::spam_report()
{
  return x_spam_report;
}

string&
SpamAssassin::spam_prev_content_type()
{
  return x_spam_prev_content_type;
}

string&
SpamAssassin::spam_checker_version()
{
  return x_spam_checker_version;
}

string&
SpamAssassin::spam_level()
{
  return x_spam_level;
}

string&
SpamAssassin::content_type()
{
  return _content_type;
}

string&
SpamAssassin::subject()
{
  return _subject;
}

string&
SpamAssassin::rcpt()
{
  return _rcpt;
}

string&
SpamAssassin::from()
{
  return _from;
}

string&
SpamAssassin::connectip()
{
  return _connectip;
}


string
SpamAssassin::local_user()
{
  // assuming we have a recipient in the form: <username@somehost.somedomain>
  // (angle brackets optional) we return 'username'
  if (_rcpt[0] == '<')
    return _rcpt.substr(1, _rcpt.find_first_of("@+")-1);
  else
  	return _rcpt.substr(0, _rcpt.find_first_of("@+"));
}

string
SpamAssassin::full_user()
{
  string name;
  // assuming we have a recipient in the form: <username@somehost.somedomain>
  // (angle brackets optional) we return 'username@somehost.somedomain'
  if (_rcpt[0] == '<')
    name = _rcpt.substr(1, _rcpt.find('>')-1);
  else
  	name = _rcpt;
  if(name.find('@') == string::npos)
  {
    /* if the name had no domain part (local delivery), append the default one */
    name = name + "@" + defaultdomain;
  }
  return name;
}

int
SpamAssassin::numrcpt()
{
  return _numrcpt;
}

int
SpamAssassin::set_numrcpt()
{
  _numrcpt++;
  return _numrcpt;
}

int
SpamAssassin::set_numrcpt(const int val)
{
  _numrcpt = val;
  return _numrcpt;
}

//
// set the values of the different SpamAssassin
// fields in our element. Returns former size of field
//
string::size_type
SpamAssassin::set_spam_status(const string& val)
{
  string::size_type old = x_spam_status.size();
  x_spam_status = val;
  return (old);
}

string::size_type
SpamAssassin::set_spam_flag(const string& val)
{
  string::size_type old = x_spam_flag.size();
  x_spam_flag = val;
  return (old);
}

string::size_type
SpamAssassin::set_spam_report(const string& val)
{
  string::size_type old = x_spam_report.size();
  x_spam_report = val;
  return (old);
}

string::size_type
SpamAssassin::set_spam_prev_content_type(const string& val)
{
  string::size_type old = x_spam_prev_content_type.size();
  x_spam_prev_content_type = val;
  return (old);
}

string::size_type
SpamAssassin::set_spam_checker_version(const string& val)
{
  string::size_type old = x_spam_checker_version.size();
  x_spam_checker_version = val;
  return (old);
}

string::size_type
SpamAssassin::set_spam_level(const string& val)
{
  string::size_type old = x_spam_level.size();
  x_spam_level = val;
  return (old);
}

string::size_type
SpamAssassin::set_content_type(const string& val)
{
  string::size_type old = _content_type.size();
  _content_type = val;
  return (old);
}

string::size_type
SpamAssassin::set_subject(const string& val)
{
  string::size_type old = _subject.size();
  _subject = val;
  return (old);
}

string::size_type
SpamAssassin::set_rcpt(const string& val)
{
  string::size_type old = _rcpt.size();
  _rcpt = val;
  return (old);
}

string::size_type
SpamAssassin::set_from(const string& val)
{
  string::size_type old = _from.size();
  _from = val;
  return (old);
}

string::size_type
SpamAssassin::set_connectip(const string& val)
{
  string::size_type old = _connectip.size();
  _connectip = val;
  return (old);
}

//
// Read available output from SpamAssassin client
//
int
SpamAssassin::read_pipe()
{
	long size;
	int  status;
	char iobuff[1024];
	string reason;

	debug(D_FUNC, "::read_pipe enter");

	if (pipe_io[1][0] == -1)
	{
		debug(D_FUNC, "::read_pipe exit - shouldn't have been called?");
		return 0;
	}

	size = read(pipe_io[1][0], iobuff, 1024);

	if (size < 0)
    {
		// Error.
		reason = string(strerror(errno));

		// Close remaining pipe.
		close(pipe_io[1][0]);
		pipe_io[1][0] = -1;

		// Slaughter child
		kill(pid, SIGKILL);

		// set flags
		error = true;
		running = false;

		// wait until child is dead
		waitpid(pid, &status, 0);

		// throw the error message that caused this trouble
		throw string(string("read error: ")+reason);
	} else if ( size == 0 )
	{

		// EOF. Close the pipe
		if(close(pipe_io[1][0]))
			throw string(string("close error: ")+string(strerror(errno)));
		pipe_io[1][0] = -1;

	} else
	{
		// append to mail buffer
		mail.append(iobuff, size);
		debug(D_POLL, "read %ld bytes", size);
		debug(D_SPAMC, "input  \"%*.*s\"", (int)size, (int)size, iobuff);
	}
	debug(D_FUNC, "::read_pipe exit");
	return size;
}

//
// Read all output from SpamAssassin client
// and close the pipe
//
void
SpamAssassin::empty_and_close_pipe()
{
	debug(D_FUNC, "::empty_and_close_pipe enter");
	while (read_pipe())
		;
	debug(D_FUNC, "::empty_and_close_pipe exit");
}

// }}}

// {{{ Some small subroutines without much relation to functionality

// output error message to syslog facility
void
throw_error(const string& errmsg)
{
  if (errmsg.c_str())
    syslog(LOG_ERR, "Thrown error: %s", errmsg.c_str());
  else
    syslog(LOG_ERR, "Unknown error");
}

/* Takes a comma or space-delimited string of debug tokens and sets the
   appropriate bits in flag_debug.  "all" sets all the bits.
*/
void parse_debuglevel(char* string)
{
	char *token;

	/* make a copy so we don't overwrite argv[] */
	string = strdup(string);

	/* handle the old numeric values too */
	switch(atoi(string))
	{
		case 3:
			flag_debug |= (1<<D_UORI) | (1<<D_STR);
		case 2:
			flag_debug |= (1<<D_POLL);
		case 1:
			flag_debug |= (1<<D_MISC) | (1<<D_FUNC);
			debug(D_ALWAYS, "Setting debug level to 0x%0x", flag_debug);
			free(string);
			return;
		default:
			break;
	}

	while ((token = strsep(&string, ", ")))
	{
		int i;
		for (i=0; debugstrings[i]; i++)
		{
			if(strcasecmp(token, "ALL")==0)
			{
				flag_debug = (1<<D_MAX)-1;
				break;
			}
			if(strcasecmp(token, debugstrings[i])==0)
			{
				flag_debug |= (1<<i);
				break;
			}
		}

		if (!debugstrings[i])
		{
			fprintf(stderr, "Invalid debug token \"%s\"\n", token);
			exit(1);
		}
	}
	debug(D_ALWAYS, "Setting debug level to 0x%0x", flag_debug);
	free(string);
}

/*
   Output a line to syslog using print format, but only if the appropriate
   debug level is set.  The D_ALWAYS level is always enabled.
*/
void debug(enum debuglevel level, const char* fmt, ...)
{
	if ((1<<level) & flag_debug)
	{
#if defined(HAVE_VSYSLOG)
		va_list vl;
		va_start(vl, fmt);
		vsyslog(LOG_ERR, fmt, vl);
		va_end(vl);
#else
#if defined(HAVE_VASPRINTF)
		char *buf;
#else
		char buf[1024];
#endif
		va_list vl;
		va_start(vl, fmt);
#if defined(HAVE_VASPRINTF)
		vasprintf(&buf, fmt, vl);
#else
#if defined(HAVE_VSNPRINTF)
		vsnprintf(buf, sizeof(buf)-1, fmt, vl);
#else
		/* XXX possible buffer overflow here; be careful what you pass to debug() */
		vsprintf(buf, fmt, vl);
#endif
#endif
		va_end(vl);
		syslog(LOG_ERR, "%s", buf);
#if defined(HAVE_VASPRINTF)
		free(buf);
#endif
#endif /* vsyslog */
	}
}

// case-insensitive search
string::size_type
find_nocase(const string& array, const string& pattern, string::size_type start)
{
  string::size_type pos(start);

  while (pos < array.size())
    {
      string::size_type ctr = 0;

      while( (pos+ctr) < array.size() &&
	     toupper(array[pos+ctr]) == toupper(pattern[ctr]) )
	{
	  ++ctr;
	  if (ctr == pattern.size())
	  {
	    debug(D_STR, "f_nc: <%s><%s>: hit", array.c_str(), pattern.c_str());
	    return pos;
	  }
	};

      ++pos;
    };

  debug(D_STR, "f_nc: <%s><%s>: nohit", array.c_str(), pattern.c_str());
  return string::npos;
}

// compare case-insensitive
int
cmp_nocase_partial(const string& s, const string& s2)
{
  string::const_iterator p=s.begin();
  string::const_iterator p2=s2.begin();

  while ( p != s.end() && p2 <= s2.end() ) {
    if (toupper(*p) != toupper(*p2))
    {
      debug(D_STR, "c_nc_p: <%s><%s> : miss", s.c_str(), s2.c_str());
      return (toupper(*p) < toupper(*p2)) ? -1 : 1;
    }
    ++p;
    ++p2;
  };

  debug(D_STR, "c_nc_p: <%s><%s> : hit", s.c_str(), s2.c_str());
  return 0;

}

/* closeall() - close all FDs >= a specified value */
void closeall(int fd)
{
	int fdlimit = sysconf(_SC_OPEN_MAX);
	while (fd < fdlimit)
		close(fd++);
}

void parse_networklist(char *string, struct networklist *list)
{
	char *token;

	/* make a copy so we don't overwrite argv[] */
	string = strdup(string);

	while ((token = strsep(&string, ", ")))
	{
		char *tnet = strsep(&token, "/");
		char *tmask = token;
		struct in_addr net;
		struct in6_addr net6;

		if (list->num_nets % 10 == 0)
			list->nets = (union net*)realloc(list->nets, sizeof(*list->nets) * (list->num_nets + 10));

		if (inet_pton(AF_INET, tnet, &net))
		{
			struct in_addr mask;

			if (tmask)
			{
				if (strchr(tmask, '.') == NULL)
				{
					/* CIDR */
					unsigned int bits;
					int ret;
					ret = sscanf(tmask, "%u", &bits);
					if (ret != 1 || bits > 32)
					{
						fprintf(stderr,"%s: bad CIDR value", tmask);
						exit(1);
					}
					mask.s_addr = htonl(~((1L << (32 - bits)) - 1) & 0xffffffff);
				} else if (!inet_pton(AF_INET6, tmask, &mask))
				{
					fprintf(stderr, "Could not parse \"%s\" as a netmask\n", tmask);
					exit(1);
				}
			} else
				mask.s_addr = 0xffffffff;

			{
				char *snet = strdup(inet_ntoa(net));
				debug(D_MISC, "Adding %s/%s to network list", snet, inet_ntoa(mask));
				free(snet);
			}

			net.s_addr = net.s_addr & mask.s_addr;
			list->nets[list->num_nets].net4.af = AF_INET;
			list->nets[list->num_nets].net4.network = net;
			list->nets[list->num_nets].net4.netmask = mask;
			list->num_nets++;
		} else if (inet_pton(AF_INET6, tnet, &net6))
		{
			int mask;

			if (tmask)
			{
				if (sscanf(tmask, "%d", &mask) != 1 || mask > 128)
				{
					fprintf(stderr,"%s: bad CIDR value", tmask);
					exit(1);
				}
			} else
				mask = 128;

			list->nets[list->num_nets].net6.af = AF_INET6;
			list->nets[list->num_nets].net6.network = net6;
			list->nets[list->num_nets].net6.netmask = mask;
			list->num_nets++;
		} else
		{
			fprintf(stderr, "Could not parse \"%s\" as a network\n", tnet);
			exit(1);
		}

	}
	free(string);
}

int ip_in_networklist(struct sockaddr *addr, struct networklist *list)
{
	int i;

	if (list->num_nets == 0)
		return 0;

	//debug(D_NET, "Checking %s against:", inet_ntoa(ip));
	for (i = 0; i < list->num_nets; i++)
	{
		if (list->nets[i].net.af == AF_INET && addr->sa_family == AF_INET)
		{
			struct in_addr ip = ((struct sockaddr_in *)addr)->sin_addr;

			debug(D_NET, "%s", inet_ntoa(list->nets[i].net4.network));
			debug(D_NET, "/%s", inet_ntoa(list->nets[i].net4.netmask));
			if ((ip.s_addr & list->nets[i].net4.netmask.s_addr) == list->nets[i].net4.network.s_addr)
			{
				debug(D_NET, "Hit!");
				return 1;
			}
		} else if (list->nets[i].net.af == AF_INET6 && addr->sa_family == AF_INET6)
		{
			u_int8_t *ip = ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
			int mask, j;

			mask = list->nets[i].net6.netmask;
			for (j = 0; j < 16 && mask > 0; j++, mask -= 8)
			{
				unsigned char bytemask;

				bytemask = (mask < 8) ? ~((1L << (8 - mask)) - 1) : 0xff;

				if ((ip[j] & bytemask) != (list->nets[i].net6.network.s6_addr[j] & bytemask))
					break;
			}

			if (mask <= 0)
			{
				debug(D_NET, "Hit!");
				return 1;
			}
		}
	}

	return 0;
}

void parse_addresslist(char *string, struct addresslist *list)
{
   char *token;

   /* make a copy so we don't overwrite argv[] */
   string = strdup(string);

   while ((token = strsep(&string, ", ")))
   {
      char *addr = (char *)malloc(strlen(token)+3);
      addr = strcat(addr,"<");
      addr = strcat(addr,token);
      addr = strcat(addr,">");

      if (list->num_addrs % 10 == 0)
         list->addrs = (char **)realloc(list->addrs, sizeof(*list->addrs) * (list->num_addrs + 10));

      if (strchr(addr, '@') == NULL || strchr(addr, '.') == NULL || strchr(addr, '@') > strrchr(addr, '.'))
      {
         fprintf(stderr, "Could not parse \"%s\" as an email address\n", addr);
         exit(1);
      }


      {
         debug(D_MISC, "Adding %s to address list", addr);
      }

      list->addrs[list->num_addrs] = addr;
      list->num_addrs++;
   }
   free(string);
}

int addr_in_addresslist(char *addr, struct addresslist *list)
{
   int i;

   if (list->num_addrs == 0)
      return 0;

   if (addr == NULL)
   {
      debug(D_RCPT, "Cannot check a null address");
      return 0;
   }

   if (strcmp(addr,"") == 0)
   {
      debug(D_RCPT, "Cannot check a blank address");
      return 0;
   }

   debug(D_RCPT, "Checking %s against:", addr);
   for (i = 0; i < list->num_addrs; i++)
   {
      debug(D_RCPT, "%s", list->addrs[i]);
      if (strcmp(addr,list->addrs[i]) == 0)
      {
         debug(D_RCPT, "Hit!");
         return 1;
      }
   }

   return 0;
}

char *strlwr(char *str)
{
    char *s = str;
    while (*s)
    {
        *s = tolower(*s);
        s++;
    }
    return str;
}

/* Log a message about missing milter macros, but only the first time */
void warnmacro(const char *macro, const char *scope)
{
	if (warnedmacro)
		return;
	debug(D_ALWAYS, "Could not retrieve sendmail macro \"%s\"!.  Please add it to confMILTER_MACROS_%s for better spamassassin results",
		macro, scope);
	warnedmacro = true;
}

/*
   untrusted-argument-safe popen function - only supports "r" and "w" modes
   for simplicity, and always reads stdout and stderr in "r" mode.  Call
   fclose to close the FILE, and waitpid to reap the child process (pid).
*/
FILE *popenv(char *const argv[], const char *type, pid_t *pid)
{
	FILE *iop;
	int pdes[2];
	int save_errno;

	if ((*type != 'r' && *type != 'w') || type[1])
	{
		errno = EINVAL;
		return (NULL);
	}
	if (pipe(pdes) < 0)
		return (NULL);
	switch (*pid = fork()) {

	case -1:			/* Error. */
		save_errno = errno;
		(void)close(pdes[0]);
		(void)close(pdes[1]);
		errno = save_errno;
		return (NULL);
		/* NOTREACHED */
	case 0:				/* Child. */
		if (*type == 'r') {
			/*
			 * The dup2() to STDIN_FILENO is repeated to avoid
			 * writing to pdes[1], which might corrupt the
			 * parent's copy.  This isn't good enough in
			 * general, since the exit() is no return, so
			 * the compiler is free to corrupt all the local
			 * variables.
			 */
			(void)close(pdes[0]);
			(void)dup2(pdes[1], STDOUT_FILENO);
			(void)dup2(pdes[1], STDERR_FILENO);
			if (pdes[1] != STDOUT_FILENO && pdes[1] != STDERR_FILENO) {
				(void)close(pdes[1]);
			}
		} else {
			if (pdes[0] != STDIN_FILENO) {
				(void)dup2(pdes[0], STDIN_FILENO);
				(void)close(pdes[0]);
			}
			(void)close(pdes[1]);
		}
		execv(argv[0], argv);
		exit(127);
		/* NOTREACHED */
	}

	/* Parent; assume fdopen can't fail. */
	if (*type == 'r') {
		iop = fdopen(pdes[0], type);
		(void)close(pdes[1]);
	} else {
		iop = fdopen(pdes[1], type);
		(void)close(pdes[0]);
	}

	return (iop);
}

// }}}
// vim6:ai:noexpandtab
