/*
 * Copyright (c) 2015 The Regents of the University of china.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
char copyright[] =
  "@(#) Copyright (c) 1980, 1987, 1988 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] __attribute__ ((used)) =
  "@(#)login.c	5.32.1.1 (Berkeley) 1/28/89, 1.10 (Cygwin) 2009-04-20";
#endif /* not lint */

/*
 * login [ name ]
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
 */

#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/termios.h>

#include <utmp.h>
#include <signal.h>
#include <lastlog.h>
#include <errno.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdio.h>
#include <strings.h>

#define	TTYGRPNAME	"tty"	/* name of group to own ttys */

#define	MOTDFILE	"/etc/motd"
#define	MAILDIR		"/usr/spool/mail"
#define	NOLOGIN		"/etc/nologin"
#define	HUSHLOGIN	".hushlogin"
#ifdef __CYGWIN__
#define	LASTLOG		"/var/log/lastlog"
#else
#define	LASTLOG		"/usr/adm/lastlog"
#endif
#define	BSHELL		"/bin/sh"

#ifdef __CYGWIN__
#include <windows.h>
#include <sys/cygwin.h>
#endif

#ifdef __CYGWIN__
static int isROOT_UID (uid_t uid);
#else
#define isROOT_UID(uid) ((int) ((uid) == 0))
#endif

static void getloginname ();
static void timedout ();
static void motd ();
static void sigint ();
static void checknologin ();
static void dolastlog (int quiet);
static void badlogin (char *name);
static void sleepexit (int eval);

/*
 * This bounds the time given to login.  Not a define so it can
 * be patched on machines where it's too small.
 */
int timeout = 300;

struct passwd *pwd;
int failures;
char term[64], *hostname, *username, *tty;

int
main (int argc, char **argv)
{
#ifndef __CYGWIN__	/* Avoid warnings. */
  extern int errno, optind;
  extern char *optarg, **environ;
  struct group *gr;
  int ioctlval;
#endif
  register int ch;
  register char *p;
  int ask, fflag, hflag, pflag, cnt;
  int quietlog, passwd_req;
#ifdef __CYGWIN__
  gid_t priv_gid;
  uid_t priv_uid;
#endif
#ifndef __CYGWIN__	/* Avoid warnings. */
  char *salt, *envinit[1];
#endif
  char *domain, *ttyn, *pp;
  char tbuf[MAXPATHLEN + 2];
  char *ttyname (), *crypt (), *getpass ();
  time_t time ();
  off_t lseek ();

  (void) signal (SIGALRM, timedout);
  (void) alarm ((u_int) timeout);
  (void) signal (SIGQUIT, SIG_IGN);
  (void) signal (SIGINT, SIG_IGN);

  /*
   * -p is used by getty to tell login not to destroy the environment
   * -f is used to skip a second login authentication 
   * -h is used by other servers to pass the name of the remote
   *    host to login so that it may be placed in utmp and wtmp
   */
  (void) gethostname (tbuf, sizeof (tbuf));
  domain = index (tbuf, '.');

  fflag = hflag = pflag = 0;
  passwd_req = 1;
  while ((ch = getopt (argc, argv, "fh:p")) != EOF)
    switch (ch)
      {
      case 'f':
	fflag = 1;
	break;
      case 'h':
#ifndef __CYGWIN__
	if (!isROOT_UID (getuid ()))
	  {
	    fprintf (stderr, "login: -h for super-user only.\n");
	    exit (1);
	  }
#endif
	hflag = 1;
	if (domain && (p = index (optarg, '.')) &&
	    strcasecmp (p, domain) == 0)
	  *p = 0;
	hostname = optarg;
	break;
      case 'p':
	pflag = 1;
	break;
      case '?':
      default:
	fprintf (stderr, "usage: login [-fp] [username]\n");
	exit (1);
      }
  argc -= optind;
  argv += optind;
  if (*argv)
    {
      username = *argv;
      ask = 0;
    }
  else
    ask = 1;

  for (cnt = getdtablesize (); cnt > 2; cnt--)
    close (cnt);

  ttyn = ttyname (0);
  if (ttyn == NULL || *ttyn == '\0')
    ttyn = "/dev/tty??";
  if ((tty = rindex (ttyn, '/')))
    ++tty;
  else
    tty = ttyn;

  openlog ("login", LOG_ODELAY, LOG_AUTH);

  for (cnt = 0;; ask = 1)
    {
#ifndef __CYGWIN__
      ioctlval = 0;
      (void) ioctl (0, TIOCSETD, &ioctlval);
#endif
      if (ask)
	{
	  fflag = 0;
	  getloginname ();
	}
      /*
       * Note if trying multiple user names;
       * log failures for previous user name,
       * but don't bother logging one failure
       * for nonexistent name (mistyped username).
       */
      if (failures && strcmp (tbuf, username))
	{
	  if (failures > (pwd ? 0 : 1))
	    badlogin (tbuf);
	  failures = 0;
	}
      (void) strcpy (tbuf, username);
#ifdef __CYGWIN__
      pwd = getpwnam (username);
#else
      if (pwd = getpwnam (username))
	salt = pwd->pw_passwd;
      else
	salt = "xx";
#endif
      /* if user not super-user, check for disabled logins */
      if (pwd == NULL || !isROOT_UID (pwd->pw_uid))
	checknologin ();

      /*
       * Disallow automatic login to root; if not invoked by
       * root, disallow if the uid's differ.
       */
      if (fflag && pwd)
	{
	  int uid = getuid ();

	  passwd_req = isROOT_UID (pwd->pw_uid) ||
	    ((!isROOT_UID (uid)) && (uid != pwd->pw_uid));
	}

      /*
       * If no pre-authentication and a password exists
       * for this user, prompt for one and verify it.
       */
      if (!passwd_req || (pwd && !*pwd->pw_passwd))
	break;

      pp = getpass ("Password:");
#ifdef __CYGWIN__
	{
	  HANDLE hToken = cygwin_logon_user (pwd, pp);
	  if (hToken != INVALID_HANDLE_VALUE)
	    {
	      cygwin_set_impersonation_token (hToken);
	      break;
	    }
	}
#else
	{
	  p = crypt (pp, salt);
	  if (pwd && !strcmp (p, pwd->pw_passwd))
	    break;
	}
#endif
      (void) bzero (pp, strlen (pp));

      printf ("Login incorrect\n");
      failures++;
      /* we allow 10 tries, but after 3 we start backing off */
      if (++cnt > 3)
	{
	  if (cnt >= 10)
	    {
	      badlogin (username);
#ifndef __CYGWIN__
	      (void) ioctl (0, TIOCHPCL, (struct sgttyb *) NULL);
#endif
	      sleepexit (1);
	    }
	  sleep ((u_int) ((cnt - 3) * 5));
	}
    }

  /* committed to login -- turn off timeout */
  (void) alarm ((u_int) 0);
  /*
   * If valid so far and root is logging in, see if root logins on
   * this terminal are permitted.
   */
#ifdef __CYGWIN__
  /* Unfortunately we have to make sure that the user is already
     the right one to chmod to its home dir on Windows. */
  priv_gid = getegid ();
  priv_uid = geteuid ();
  setegid (pwd->pw_gid);
  if (seteuid (pwd->pw_uid))
    {
      printf ("Switching to user %s failed!\n", username);
      sleep (1);
      exit (0);
    }
#endif
  if (chdir (pwd->pw_dir) < 0)
    {
      printf ("No directory %s!\n", pwd->pw_dir);
      if (chdir ("/"))
	exit (0);
      pwd->pw_dir = "/";
      printf ("Logging in with home = \"/\".\n");
    }
  /* nothing else left to fail -- really log in */
#ifdef __CYGWIN__
  /* But we have to revert to the privileged user to access utmp. */
  setegid (priv_gid);
  seteuid (priv_uid);
#endif
  {
    struct utmp utmp;

    bzero ((char *) &utmp, sizeof (utmp));
    (void) time (&utmp.ut_time);
    strncpy (utmp.ut_name, username, sizeof (utmp.ut_name));
    if (hostname)
      strncpy (utmp.ut_host, hostname, sizeof (utmp.ut_host));
    strncpy (utmp.ut_line, tty, sizeof (utmp.ut_line));
#ifdef __CYGWIN__
    /* Cygwin has the Linux fields in utmp as well. */
    {
      int len = strlen (tty) - sizeof (utmp.ut_id);
      if (len > 0)
	tty += len;
      strncpy (utmp.ut_id, tty, sizeof (utmp.ut_id));
      if (len > 0)
	tty -= len;
      utmp.ut_pid = getpid ();
    }
#endif
    utmp.ut_type = USER_PROCESS;
    login (&utmp);
  }
  quietlog = access (HUSHLOGIN, F_OK) == 0;
  dolastlog (quietlog);

  setgid (pwd->pw_gid);
  setuid (pwd->pw_uid);

#if 0
  if (!hflag)
    {				/* XXX */
      static struct winsize win = { 0, 0 /*, 0, 0 */  };

      (void) ioctl (0, TIOCSWINSZ, &win);
    }
#endif

#ifndef __CYGWIN__
  initgroups (username, pwd->pw_gid);
#endif

  if (*pwd->pw_shell == '\0')
    pwd->pw_shell = BSHELL;

  /* destroy environment unless user has requested preservation */
#ifndef __CYGWIN__
  if (!pflag)
    environ = envinit;
#endif
  (void) setenv ("HOME", pwd->pw_dir, 1);
  (void) setenv ("SHELL", pwd->pw_shell, 1);
#ifndef __CYGWIN__
  (void) setenv ("TERM", term, 0);
#endif
  (void) setenv ("USER", pwd->pw_name, 1);
  (void) setenv ("PATH", "/usr/ucb:/bin:/usr/bin:", 0);

  if (tty[sizeof ("tty") - 1] == 'd')
    syslog (LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
  if (isROOT_UID (pwd->pw_uid))
    {
      if (hostname)
	syslog (LOG_NOTICE, "ROOT LOGIN ON %s FROM %s", tty, hostname);
      else
	syslog (LOG_NOTICE, "ROOT LOGIN ON %s", tty);
    }

  if (!quietlog)
    {
      struct stat st;

      motd ();
      (void) sprintf (tbuf, "%s/%s", MAILDIR, pwd->pw_name);
      if (stat (tbuf, &st) == 0 && st.st_size != 0)
	printf ("You have %smail.\n",
		(st.st_mtime > st.st_atime) ? "new " : "");
    }

  (void) signal (SIGALRM, SIG_DFL);
  (void) signal (SIGQUIT, SIG_DFL);
  (void) signal (SIGINT, SIG_DFL);
  (void) signal (SIGTSTP, SIG_IGN);

  tbuf[0] = '-';
  strcpy (tbuf + 1, (p = rindex (pwd->pw_shell, '/')) ?
	  p + 1 : pwd->pw_shell);
  execlp (pwd->pw_shell, tbuf, NULL);
  fprintf (stderr, "login: no shell: ");
  perror (pwd->pw_shell);
  exit (0);
}

static void
getloginname ()
{
  register int ch;
  register char *p;
  static char nbuf[UT_NAMESIZE + 1];

  for (;;)
    {
      printf ("login: ");
      for (p = nbuf; (ch = getchar ()) != '\n';)
	{
	  if (ch == EOF)
	    {
	      badlogin (username);
	      exit (0);
	    }
	  if (p < nbuf + UT_NAMESIZE)
	    *p++ = ch;
	}
      if (p > nbuf)
	{
	  if (nbuf[0] == '-')
	    fprintf (stderr, "login names may not start with '-'.\n");
	  else
	    {
	      *p = '\0';
	      username = nbuf;
	      break;
	    }
	}
    }
}

static void
timedout ()
{
  fprintf (stderr, "Login timed out after %d seconds\n", timeout);
  exit (0);
}

jmp_buf motdinterrupt;

static void
motd ()
{
  register int fd, nchars;
  void (*oldint) ();
  char tbuf[8192];

  if ((fd = open (MOTDFILE, O_RDONLY, 0)) < 0)
    return;
  oldint = signal (SIGINT, sigint);
  if (setjmp (motdinterrupt) == 0)
    while ((nchars = read (fd, tbuf, sizeof (tbuf))) > 0)
      (void) write (fileno (stdout), tbuf, nchars);
  (void) signal (SIGINT, oldint);
  (void) close (fd);
}

static void
sigint ()
{
  longjmp (motdinterrupt, 1);
}

static void
checknologin ()
{
  register int fd, nchars;
  char tbuf[8192];

  if ((fd = open (NOLOGIN, O_RDONLY, 0)) >= 0)
    {
      while ((nchars = read (fd, tbuf, sizeof (tbuf))) > 0)
	(void) write (fileno (stdout), tbuf, nchars);
      sleepexit (0);
    }
}

static void
dolastlog (int quiet)
{
  struct lastlog ll;
  int fd;

  if ((fd = open (LASTLOG, O_RDWR, 0)) >= 0)
    {
      (void) lseek (fd, (off_t) pwd->pw_uid * sizeof (ll), L_SET);
      if (!quiet)
	{
	  if (read (fd, (char *) &ll, sizeof (ll)) == sizeof (ll) &&
	      ll.ll_time != 0)
	    {
	      printf ("Last login: %.*s ",
		      24 - 5, (char *) ctime (&ll.ll_time));
	      if (*ll.ll_host != '\0')
		printf ("from %.*s\n", (int) sizeof (ll.ll_host), ll.ll_host);
	      else
		printf ("on %.*s\n", (int) sizeof (ll.ll_line), ll.ll_line);
	    }
	  (void) lseek (fd, (off_t) pwd->pw_uid * sizeof (ll), L_SET);
	}
      bzero ((char *) &ll, sizeof (ll));
      (void) time (&ll.ll_time);
      strncpy (ll.ll_line, tty, sizeof (ll.ll_line));
      if (hostname)
	strncpy (ll.ll_host, hostname, sizeof (ll.ll_host));
      (void) write (fd, (char *) &ll, sizeof (ll));
      (void) close (fd);
    }
}

static void
badlogin (char *name)
{
  if (failures == 0)
    return;
  if (hostname)
    syslog (LOG_NOTICE, "%d LOGIN FAILURE%s FROM %s, %s",
	    failures, failures > 1 ? "S" : "", hostname, name);
  else
    syslog (LOG_NOTICE, "%d LOGIN FAILURE%s ON %s, %s",
	    failures, failures > 1 ? "S" : "", tty, name);
}

static void
sleepexit (int eval)
{
  sleep ((u_int) 5);
  exit (eval);
}

#ifdef __CYGWIN__

extern int uidIsLocalSystem (uid_t uid);
extern int uidIsMemberOfLocalAdministrators (uid_t uid);
extern int testUserRightsByUID (uid_t uid, const char **strRightsToTest,
				ULONG intRightsToTestCount);

static int
isROOT_UID (uid_t uid)
{
  static const char *REQUIRED_PRIVS[] = {
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeIncreaseQuotaPrivilege"
  };
  static const ULONG NUM_REQUIRED_PRIV = 3;

  OSVERSIONINFOEX osvi;
  struct passwd *pw;

  ZeroMemory (&osvi, sizeof (OSVERSIONINFOEX));
  osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
  if (!GetVersionEx ((OSVERSIONINFO *) & osvi))
    return 0;			/* not a root id */

  if (osvi.dwMajorVersion == 5)
    {
      /* Windows Server 2003 R2, Windows Server 2003, or Windows XP. */
      if (osvi.dwMinorVersion < 2)
	{
	  /* XP: check for LocalSystem */
	  if (uidIsLocalSystem (uid) == 0)
	    return 1;		/* yes, LocalSystem! */

	  /* otherwise, need to check capabilities */
	}
    }

  /* check capabilities */
  pw = getpwuid (uid);

  /* not in /etc/passwd. say it is not root. */
  if (!pw)
    return 0;

  /* check for membership in BUILTIN\Administrators */
  if (uidIsMemberOfLocalAdministrators (uid) != 0)
    return 0;

  /* returns non-zero if the account DOES have all specified privileges */
  return testUserRightsByUID (uid, REQUIRED_PRIVS, NUM_REQUIRED_PRIV);
}
#endif
