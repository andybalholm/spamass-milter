//-*-c++-*-
//
//  $Id: spamass-milter.h,v 1.2 2002/01/31 15:28:50 greve Exp $
//
//  Main include file for SpamAss-Milter
//


string retrieve_field(const string&, const string&);

sfsistat mlfi_envfrom(SMFICTX*, char**);
sfsistat mlfi_header(SMFICTX*, char*, char*);
sfsistat mlfi_eoh(SMFICTX*);
sfsistat mlfi_body(SMFICTX*, u_char *, size_t);
sfsistat mlfi_eom(SMFICTX*);
sfsistat mlfi_close(SMFICTX*);
sfsistat mlfi_abort(SMFICTX*);
sfsistat mlfi_abort(SMFICTX*);

struct smfiDesc smfilter =
  {
    "SpamAssassin", // filter name
    SMFI_VERSION,   // version code -- leave untouched
    SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_CHGBODY,  // flags
    NULL, // info filter callback
    NULL, // HELO filter callback
    mlfi_envfrom, // envelope filter callback
    NULL, // envelope recipient filter callback
    mlfi_header, // header filter callback
    mlfi_eoh, // end of header callback
    mlfi_body, // body filter callback
    mlfi_eom, // end of message callback
    mlfi_abort, // message aborted callback
    mlfi_close, // connection cleanup callback
  };

class SpamAssassin {
public:
  SpamAssassin();
  ~SpamAssassin();

  void output(const void*, long);
  void close_output();
  void input();

  string& d();

  string& spam_status();
  string& spam_flag();
  string& spam_report();
  string& spam_prev_content_type();
  string& spam_checker_version();
  string& content_type();
  string& subject();
  string::size_type set_spam_status(const string&);
  string::size_type set_spam_flag(const string&);
  string::size_type set_spam_report(const string&);
  string::size_type set_spam_prev_content_type(const string&);
  string::size_type set_spam_checker_version(const string&);
  string::size_type set_content_type(const string&);
  string::size_type set_subject(const string&);

private:
  void empty_and_close_pipe();

public:  
  // flags
  bool error;
  bool running;

  // This is where we store the mail after it
  // was piped through SpamAssassin
  string mail;

  // Variables for SpamAssassin influenced fields
  string x_spam_status, x_spam_flag, x_spam_report, x_spam_prev_content_type;
  string x_spam_checker_version, _content_type, _subject;

  // Process handling variables
  pid_t pid;
  int pipe_io[2][2];
  
};

void assassinate(SMFICTX*, SpamAssassin*);

void throw_error(const string&);
string::size_type find_nocase(const string&, const string&, string::size_type = 0);
int cmp_nocase_partial(const string&, const string&);

