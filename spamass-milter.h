//-*-c++-*-
//
//  $Id: spamass-milter.h,v 1.16 2003/06/12 22:41:34 dnelson Exp $
//
//  Main include file for SpamAss-Milter
//
//  Copyright (c) 2002 Georg C. F. Greve <greve@gnu.org>,
//   all rights maintained by FSF Europe e.V., 
//   Villa Vogelsang, Antonienallee 1, 45279 Essen, Germany
//
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
#include <list>

using namespace std;

string retrieve_field(const string&, const string&);

sfsistat mlfi_connect(SMFICTX*, char*, _SOCK_ADDR*);
sfsistat mlfi_helo(SMFICTX*, char*);
sfsistat mlfi_envrcpt(SMFICTX*, char**);
sfsistat mlfi_envfrom(SMFICTX*, char**);
sfsistat mlfi_header(SMFICTX*, char*, char*);
sfsistat mlfi_eoh(SMFICTX*);
sfsistat mlfi_body(SMFICTX*, u_char *, size_t);
sfsistat mlfi_eom(SMFICTX*);
sfsistat mlfi_close(SMFICTX*);
sfsistat mlfi_abort(SMFICTX*);
sfsistat mlfi_abort(SMFICTX*);

extern struct smfiDesc smfilter;

/* struct describing a single network */
struct net
{
	struct in_addr network;
	struct in_addr netmask;
};

/* an array of networks */
struct networklist
{
	struct net *nets;
	int num_nets;
};


// Debug tokens.
enum debuglevel 
{
	D_ALWAYS, D_FUNC, D_POLL, D_UORI, D_STR, D_MISC, D_NET, D_SPAMC,
	D_MAX // must be last
};

class SpamAssassin {
public:
  SpamAssassin();
  ~SpamAssassin();

  void Connect();
  void output(const void*, long);
  void output(const void*);
  void output(string);
  void close_output();
  void input();

  string& d();

  string& spam_status();
  string& spam_flag();
  string& spam_report();
  string& spam_prev_content_type();
  string& spam_checker_version();
  string& spam_level();
  string& content_type();
  string& subject();
  string& rcpt();
  string& from();
  string& connectip();
  string  local_user();
  int     numrcpt();
  int     set_numrcpt();
  int     set_numrcpt(const int);
  string::size_type set_spam_status(const string&);
  string::size_type set_spam_flag(const string&);
  string::size_type set_spam_report(const string&);
  string::size_type set_spam_prev_content_type(const string&);
  string::size_type set_spam_checker_version(const string&);
  string::size_type set_spam_level(const string&);
  string::size_type set_content_type(const string&);
  string::size_type set_subject(const string&);
  string::size_type set_rcpt(const string&);
  string::size_type set_from(const string&);
  string::size_type set_connectip(const string&);

private:
  void empty_and_close_pipe();
  int read_pipe();

public:  
  // flags
  bool error;
  bool running;
  bool connected;

  // This is where we store the mail after it
  // was piped through SpamAssassin
  string mail;

  // Variables for SpamAssassin influenced fields
  string x_spam_status, x_spam_flag, x_spam_report, x_spam_prev_content_type;
  string x_spam_checker_version, x_spam_level, _content_type, _subject;
  
  // Envelope info: MAIL FROM:, RCPT TO:, and IP address of remote host
  // _rcpt only holds the first recipient if there are more than one
  string _from, _rcpt, _connectip;
  
  // Counter to keep track of the number of recipients
  int    _numrcpt;

  // The list of recipients for the current message
  list <string> recipients;

  // the sendmail queue id for this message; used for logging
  string queueid;

  // Process handling variables
  pid_t pid;
  int pipe_io[2][2];
};
  
/* Private data structure to carry per-client data between calls */
struct context
{
	struct in_addr connect_ip;	// remote IP address
	char *helo;
	SpamAssassin *assassin; // pointer to the SA object if we're processing a message
};

/* This hack is the only way to call pointers to member functions! */
typedef string::size_type (SpamAssassin::*t_setter)(const string &val);
#define callsetter(object, ptrToMember)  ((object).*(ptrToMember))
       
int assassinate(SMFICTX*, SpamAssassin*);

void throw_error(const string&);
void debug(enum debuglevel, const char* fmt, ...); /* __printflike(2, 3); */
string::size_type find_nocase(const string&, const string&, string::size_type = 0);
int cmp_nocase_partial(const string&, const string&);
void closeall(int fd);
void parse_networklist(char *string, struct networklist *list);
int ip_in_networklist(struct in_addr ip, struct networklist *list);
void parse_debuglevel(char* string);
char *strlwr(char *str);
