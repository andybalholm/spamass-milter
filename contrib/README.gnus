$Id: README.gnus,v 1.1 2002/01/16 22:16:46 greve Exp $

Supplement for GNUS users (http://www.gnus.org):

If you add the following function to your .gnus and bind it to a key,
you will be able to submit Spam to Vipul's Razor Spam Database and
expire spam that got through the SpamAssassin on a single keypress.

 (defun my-gnus-raze-spam ()
  "Submit SPAM to Vipul's Razor for a good shave, then mark it as expirable."  
  (interactive)
  (gnus-summary-show-raw-article)
  (gnus-summary-save-in-pipe "razor-report -f -d")
  (gnus-summary-mark-as-expirable 1))

Using Vipul's Razor (http://razor.sourceforge.net) seems like a very
good idea and submitting things might save others from having to see
this spam.

Of course you'll need to have the Vipul's Razor software installed.

Under Debian, "apt-get install razor" will normally do the trick.

