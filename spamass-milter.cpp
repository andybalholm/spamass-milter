// 
//
//  $Id: spamass-milter.cpp,v 1.2 2002/01/16 22:19:47 greve Exp $
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
//  Copyright (c) 2002 Georg C. F. Greve <greve@gnu.org>
//
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
//            
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
//      mail was rated spam.
//   9. free all temporary data
//   10. tell sendmail to let the mail to go on (default) or be discarded
//    -- wait for mail to show up -- (restart at 3)
//

// Includes  
#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

// C++ includes
#include <cstdio>
#include <cstddef>
#include <csignal>
#include <string>
#include <iostream>
#include <fstream>

#ifdef  __cplusplus
extern "C" {
#endif

#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"

#ifdef  __cplusplus
}
#endif

#include "spamass-milter.h"

// }}} 

// {{{ main()

int
main(int argc, char* argv[])
{
  // ONLY command line option: socket filename!
  if ( argc != 2 )
    {
      cout << "SpamAssassin Sendmail Milter Plugin" << endl;
      cout << "Usage: spamass-milter <socket>" << endl;
      _exit(0);
    };

  // set connection socket
  smfi_setconn(argv[1]);

  // register callbacks with Milter
  if (smfi_register(smfilter) == MI_FAILURE)
    {
      throw_error("smfi_register failed");
      cerr << "smfi_register failed. exit." << endl;
      exit(EX_UNAVAILABLE);
    };

  // enter Milter main routine
  return smfi_main();

};

// }}}

// {{{ Assassinate

//
// implement the changes suggested by SpamAssassin for the mail.
//
void
assassinate(SMFICTX* ctx, SpamAssassin* assassin)
{
  string::size_type old;

  // find end of header (eol in last line of header)
  // and beginning of body
  string::size_type eoh1(assassin->d().find("\n\n"));
  string::size_type eoh2(assassin->d().find("\n\r\n"));
  string::size_type eoh = ( eoh1 < eoh2 ? eoh1 : eoh2 );
  string::size_type bob = assassin->d().find_first_not_of("\r\n", eoh);


  // X-Spam-Status header //
  // find it:
  old = assassin->set_spam_status(retrieve_field(assassin->d().substr(0, eoh), 
						 string("X-Spam-Status")));

  // change if old one was present, append if non-null
  if (old > 0)
    smfi_chgheader(ctx,"X-Spam-Status",1,assassin->spam_status().size() > 0 ? 
		   const_cast<char*>(assassin->spam_status().c_str()) : NULL );
  else if (assassin->spam_status().size()>0)
      smfi_addheader(ctx, "X-Spam-Status", 
		     const_cast<char*>(assassin->spam_status().c_str()));


  // X-Spam-Flag header //
  // find it:
  old = assassin->set_spam_flag(retrieve_field(assassin->d().substr(0, eoh), string("X-Spam-Flag")));

  // change if old one was present, append if non-null
  if (old > 0)
    smfi_chgheader(ctx,"X-Spam-Flag",1,assassin->spam_flag().size() > 0 ? 
		   const_cast<char*>(assassin->spam_flag().c_str()) : NULL );
  else if (assassin->spam_flag().size()>0)
      smfi_addheader(ctx, "X-Spam-Flag", 
		     const_cast<char*>(assassin->spam_flag().c_str()));
  

  // X-Spam-Report header //
  // find it:
  old = assassin->set_spam_report(retrieve_field(assassin->d().substr(0, eoh), 
						 string("X-Spam-Report")));
    
  // change if old one was present, append if non-null
  if (old > 0)
    smfi_chgheader(ctx,"X-Spam-Report",1,assassin->spam_report().size() > 0 ? 
		   const_cast<char*>(assassin->spam_report().c_str()) : NULL );
  else if (assassin->spam_report().size()>0)
	smfi_addheader(ctx, "X-Spam-Report", 
		       const_cast<char*>(assassin->spam_report().c_str()));
  

  // X-Spam-Prev-Content-Type header //
  // find it:
  old = assassin->set_spam_prev_content_type(retrieve_field(assassin->d().substr(0, eoh), 
							    string("X-Spam-Prev-Content-Type")));
  
  // change if old one was present, append if non-null
  if (old > 0)
    smfi_chgheader(ctx,"X-Spam-Prev-Content-Type",1,assassin->spam_prev_content_type().size() > 0 ? 
		   const_cast<char*>(assassin->spam_prev_content_type().c_str()) : NULL );
  else if (assassin->spam_prev_content_type().size()>0)
    smfi_addheader(ctx, "X-Spam-Prev-Content-Type", 
		   const_cast<char*>(assassin->spam_prev_content_type().c_str()));

        
  // 
  // If SpamAssassin thinks it is spam, replace
  //  Subject:
  //  Content-Type:
  //  <Body>
  // 
  if (assassin->spam_flag().size()>0)
    {

      // Subject header //
      // find it:
      old = assassin->set_subject(retrieve_field(assassin->d().substr(0, eoh), 
						 string("Subject")));
      
      // change if old one was present, append if non-null
      if (old > 0)
	smfi_chgheader(ctx,"Subject",1,assassin->subject().size() > 0 ? 
		       const_cast<char*>(assassin->subject().c_str()) : NULL );
      else if (assassin->content_type().size()>0)
	smfi_addheader(ctx, "Subject", 
		       const_cast<char*>(assassin->subject().c_str()));
      

      // Content-Type header //
      // find it:
      old = assassin->set_content_type(retrieve_field(assassin->d().substr(0, eoh), 
						      string("Content-Type")));
      
      // change if old one was present, append if non-null
      if (old > 0)
	smfi_chgheader(ctx,"Content-Type",1,assassin->content_type().size() > 0 ? 
		       const_cast<char*>(assassin->content_type().c_str()) : NULL );
      else if (assassin->content_type().size()>0)
	smfi_addheader(ctx, "Content-Type", 
		       const_cast<char*>(assassin->content_type().c_str()));
      
      
      // Replace body with the one SpamAssassin provided //
      string::size_type body_size = assassin->d().size() - bob;
      unsigned char* bodyp = (unsigned char*) 
	const_cast<char*>(assassin->d().substr(bob, string::npos).c_str());
      if ( smfi_replacebody(ctx, bodyp, body_size) == MI_FAILURE )
	throw string("error. could not replace body.");
      
    };

  // erase mail right away
  assassin->d().erase();
  
};

// retrieve the content of a specific field in the header
// and return it.
string
retrieve_field(const string& header, const string& field)
{
  // look for beginning of content
  string::size_type pos = find_nocase(header, string("\n")+field+string(": "));

  // return empty string if not found
  if (pos == string::npos)
    return string("");

  // look for end of field name
  pos = find_nocase(header, string(" "), pos) + 1;
  
  // look for end of content
  string::size_type pos2(pos);
  do {

    pos2 = find_nocase(header, string("\n"), pos2+1);

  }
  while ( pos2 < string::npos &&
	  isspace(header[pos2+1]) );

  return header.substr(pos, pos2-pos);

};

// }}}

// {{{ MLFI callbacks

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

  try {
    // launch new SpamAssassin
    assassin=new SpamAssassin;
  } catch (string& problem)
    {
      throw_error(problem);
      return SMFIS_TEMPFAIL;
    };
  
  // register the pointer to SpamAssassin object as private data
  smfi_setpriv(ctx, static_cast<void*>(assassin));

  // tell Milter to continue
  return SMFIS_CONTINUE;
};

//
// Gets called repeatedly for all header fields
//
// assembles the headers and passes them on to the SpamAssassin client
// through the pipe.
//
// only exception: SpamAssassin header fields (X-Spam-*) get suppressed
// but are being stored in the SpamAssassin element.
//
sfsistat
mlfi_header(SMFICTX* ctx, char* headerf, char* headerv)
{
  SpamAssassin* assassin = static_cast<SpamAssassin*>(smfi_getpriv(ctx));

  // Is it a "X-Spam-" header field?
  if ( cmp_nocase_partial(string("X-Spam-"), string(headerf)) == 0 )
    {
      // memorize content of old fields

      // X-Spam-Status:
      if ( cmp_nocase_partial(string("X-Spam-Status"), string(headerf)) == 0 )
	assassin->set_spam_status(string(headerv));
      
      // X-Spam-Flag:
      if ( cmp_nocase_partial(string("X-Spam-Flag"), string(headerf)) == 0 )
	assassin->set_spam_flag(string(headerv));
      
      // X-Spam-Report:
      if ( cmp_nocase_partial(string("X-Spam-Report"), string(headerf)) == 0 )
	assassin->set_spam_report(string(headerv));

      // X-Spam-Prev-Content-Type:
      if ( cmp_nocase_partial(string("X-Spam-Prev-Content-Type"), string(headerf)) == 0 )
	assassin->set_spam_prev_content_type(string(headerv));

      // ...but do not pass them on. SpamAssassin should go for it on its own.
      return SMFIS_CONTINUE;
    };

  // Content-Type: will be stored if present
  if ( cmp_nocase_partial(string("Content-Type"), string(headerf)) == 0 )
    assassin->set_content_type(string(headerv));

  // Subject: should be stored
  if ( cmp_nocase_partial(string("Subject"), string(headerf)) == 0 )
    assassin->set_subject(string(headerv));

  // assemble header to be written to SpamAssassin
  string header=string(headerf)+string(": ")+
    string(headerv)+string("\r\n");
 
  try {
    // write to SpamAssassin client
    assassin->output(header.c_str(),header.size());
  } catch (string& problem)
    {
      throw_error(problem);
      smfi_setpriv(ctx, static_cast<void*>(0));
      delete assassin;
      return SMFIS_TEMPFAIL;
    };
  
  // go on...
  return SMFIS_CONTINUE;
};

// 
// Gets called once when the header is finished.
//
// writes empty line to SpamAssassin client to separate
// headers from body.
//
sfsistat
mlfi_eoh(SMFICTX* ctx)
{
  SpamAssassin* assassin = static_cast<SpamAssassin*>(smfi_getpriv(ctx));

  try {
    // add blank line between header and body
    assassin->output("\r\n",2);
  } catch (string& problem)
    {
      throw_error(problem);
      smfi_setpriv(ctx, static_cast<void*>(0));
      delete assassin;
      return SMFIS_TEMPFAIL;
    };
  
  // go on...
  return SMFIS_CONTINUE;
};

//
// Gets called repeatedly to transmit the body
//
// writes everything directly to SpamAssassin client
//
sfsistat
mlfi_body(SMFICTX* ctx, u_char *bodyp, size_t bodylen)
{
  SpamAssassin* assassin = static_cast<SpamAssassin*>(smfi_getpriv(ctx));
 
  try {
    assassin->output(bodyp, bodylen);
  } catch (string& problem)
    {
      throw_error(problem);
      smfi_setpriv(ctx, static_cast<void*>(0));
      delete assassin;
      return SMFIS_TEMPFAIL;
    };

  // go on...
  return SMFIS_CONTINUE;
};

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
  SpamAssassin* assassin = static_cast<SpamAssassin*>(smfi_getpriv(ctx));
 
  try {

    // close output pipe to signal EOF to SpamAssassin
    assassin->close_output();

    // read what the Assassin is telling us
    assassin->input();

    // now is our chance to modify the mail accordingly to what
    // the SpamAssassin told us.
    assassinate(ctx, assassin);

    // is it SPAM?
    if (assassin->spam_flag().size()>0)
      {
	
	// true: it is SPAM! Yuck.
	throw_error(string("SpamAssassin verdict: ")+assassin->spam_status());
	
      };

    // now cleanup the element.
    smfi_setpriv(ctx, static_cast<void*>(0));
    delete assassin;

  } catch (string& problem)
    {
      throw_error(problem);
      smfi_setpriv(ctx, static_cast<void*>(0));
      delete assassin;
      return SMFIS_TEMPFAIL;
    };
  
  // go on...
  return SMFIS_CONTINUE;
};

//
// Gets called on session-basis. This keeps things nice & quiet.
//
sfsistat
mlfi_close(SMFICTX* ctx)
{
  return SMFIS_ACCEPT;
};

//
// Gets called when things are being aborted.
//
// kills the SpamAssassin object, its destructor should
// take care of everything.
//
sfsistat
mlfi_abort(SMFICTX* ctx)
{
  SpamAssassin* assassin = static_cast<SpamAssassin*>(smfi_getpriv(ctx));

  smfi_setpriv(ctx, static_cast<void*>(0));
  delete assassin;

  return SMFIS_ACCEPT;
};

// }}}

// {{{ SpamAssassin Class

SpamAssassin::SpamAssassin():
  error(false)
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

      // execute spamc 
      // absolute path (determined in autoconf) 
      // should be a little more secure
      char** argv = (char**) malloc(3*sizeof(char*));
      argv[0] = SPAMC;
      argv[1] = 0;
      execvp(argv[0] , argv); // does not return!

      // execution failed
      throw_error(string("execution error: ")+string(strerror(errno)));
      
      break;
    };

  // +++ PARENT +++

  // close unused pipes
  close(pipe_io[0][0]);
  close(pipe_io[1][1]);
  pipe_io[0][0]=-1;
  pipe_io[1][1]=-1;

  // we have to assume the client is running now.
  running=true;

};

SpamAssassin::~SpamAssassin()
{ 

  // close all pipes that are still open
  if (pipe_io[0][0] > -1)
    close(pipe_io[0][0]);

  if (pipe_io[0][1] > -1)
    close(pipe_io[0][1]);

  if (pipe_io[1][0] > -1)
    close(pipe_io[1][0]);

  if (pipe_io[1][1] > -1)
    close(pipe_io[1][1]);

  // child still running?
  if (running)
    {
      // slaughter child
      kill(pid, SIGKILL);

      // wait for child to terminate
      int status;
      waitpid(pid, &status, 0);
    };

};

// write to SpamAssassin
void
SpamAssassin::output(const void* buffer, long size)
{
  // if there are problems, fail.
  if (!running || error)
    throw string("tried output despite problems. failed.");
  
  // send to SpamAssassin
  long total(0), wsize(0);
  string reason;
  int status;
  do {
    switch(wsize=write(pipe_io[0][1], buffer, size-total))
      {
      case -1:
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
	total+=wsize;
	break;
      };
  } while ( total < size );
  
};

// close output pipe
void
SpamAssassin::close_output()
{
  if(close(pipe_io[0][1]))
    throw string(string("close error: ")+string(strerror(errno)));
  pipe_io[0][1]=-1;
};

void
SpamAssassin::input()
{
  // if the child has exited or we experienced an error, return
  // immediately.
  if (!running || error)
    return;

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
};

//
// return reference to mail
//
string& 
SpamAssassin::d()
{
  return mail;
};

//
// get values of the different SpamAssassin fields
//
string& 
SpamAssassin::spam_status()
{
  return x_spam_status;
};

string& 
SpamAssassin::spam_flag()
{
  return x_spam_flag;
};

string& 
SpamAssassin::spam_report()
{
  return x_spam_report;
};

string& 
SpamAssassin::spam_prev_content_type()
{
  return x_spam_prev_content_type;
};

string& 
SpamAssassin::content_type()
{
  return _content_type;
};

string& 
SpamAssassin::subject()
{
  return _subject;
};

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
};

string::size_type
SpamAssassin::set_spam_flag(const string& val)
{
  string::size_type old = x_spam_flag.size();
  x_spam_flag = val;
  return (old);
};

string::size_type
SpamAssassin::set_spam_report(const string& val)
{
  string::size_type old = x_spam_report.size();
  x_spam_report = val;
  return (old);
};

string::size_type
SpamAssassin::set_spam_prev_content_type(const string& val)
{
  string::size_type old = x_spam_prev_content_type.size();
  x_spam_prev_content_type = val;
  return (old);
};

string::size_type
SpamAssassin::set_content_type(const string& val)
{
  string::size_type old = _content_type.size();
  _content_type = val;
  return (old);
};

string::size_type
SpamAssassin::set_subject(const string& val)
{
  string::size_type old = _subject.size();
  _subject = val;
  return (old);
};

//
// Read all output from SpamAssassin client
// and close the pipe
//
void
SpamAssassin::empty_and_close_pipe()
{
  long size;
  char iobuff[1025];
  int  status;
  string reason;

  do {

    size=read(pipe_io[1][0],iobuff,1024);

    if (size<0)
      {

	// Error. 
	reason=string(strerror(errno));
		
	// Close remaining pipe.
	close(pipe_io[1][0]);
	pipe_io[1][0]=-1;
	
	// Slaughter child
	kill(pid, SIGKILL);
	
	// set flags
	error = true;
	running = false;
	
	// wait until child is dead
	waitpid(pid, &status, 0);
	
	// throw the error message that caused this trouble
	throw string(string("read error: ")+reason);

      }
    else if ( size == 0 )
      {

	// EOF. Close the pipe
	if(close(pipe_io[1][0]))
	  throw string(string("close error: ")+string(strerror(errno)));
	pipe_io[1][0]=-1;
	
      }
    
    // append to mail buffer 
    iobuff[size]=0;
    mail+=string(iobuff);
    
  } while (size > 0);

};

// }}}

// {{{ Some small subroutines without much relation to functionality

// output error message to syslog facility
void
throw_error(const string& errmsg)
{
  syslog(LOG_PERROR|LOG_PID|LOG_CONS|LOG_MAIL,errmsg.c_str());
};

// case-insensitive search 
string::size_type 
find_nocase(const string& array, const string& pattern, string::size_type start)
{
  string::size_type pos(start);

  while (pos < array.size())
    {
      string::size_type ctr(0);

      while( (pos+ctr) < array.size() &&
	     toupper(array[pos+ctr]) == toupper(pattern[ctr]) )
	{
	  ++ctr;
	  if (ctr == pattern.size())
	    return pos;
	};
      
      ++pos;
    };

  return string::npos;
};

// compare case-insensitive
int
cmp_nocase_partial(const string& s, const string& s2)
{
  string::const_iterator p=s.begin();
  string::const_iterator p2=s2.begin();

  while ( p != s.end() && p2 != s2.end() ) {
    if (toupper(*p) != toupper(*p2))
      return (toupper(*p) < toupper(*p2)) ? -1 : 1;
    ++p;
    ++p2;
  };

  return 0;

};

// }}}
