/* Create an MD5 file for quick ddrescue image verification
 *
 * This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 */

#define TINO_NEED_OLD_ERR_FN

#include "tino/alarm.h"
#include "tino/buf_line.h"
#include "tino/getopt.h"
#include "tino/scale.h"
#include "tino/md5.h"

#include "ddrescue-verify_version.h"

static int	errs;

struct _config
  {
    int			unbuffered, ignore, direct, relaxed, quiet;
    unsigned long	blocksize;
    unsigned long long	maxpart;
    unsigned long long	mincount;
    unsigned long long	cont;

    FILE		*out, *state;
    const char		*name;
    int			fd;
    const char		*input;

    unsigned long long	from, cnt, lastio, states, read;

    void		*block;
    unsigned long long	currentpos, currentlen;
    char		laststate;

    char		digest[33];
  };
#define	CONF	struct _config *C

static int
err(CONF, const char *s, ...)
{
  char		errbuf[256];
  va_list	list;

  va_start(list, s);
  vsnprintf(errbuf, sizeof errbuf, s, list);
  va_end(list);
  tino_err("%s at %llx(%llx): %s", C->name, C->from, C->cnt, errbuf);
  return 0;
}

static int
progress(void *user, long delta, time_t now, long runtime)
{
  CONF = user;

  if (C->quiet)
    return C->quiet==1 ? 0 : 1;

  fprintf(C->state, "\r%s %siB %s %siB/s 0x%06llx-0x%06llx %siB/s "
	, tino_scale_interval(1, runtime, 2, -6)
	, tino_scale_bytes(2, C->lastio, 2, -7)
	, tino_scale_number(3, C->states, 0, 8)
	, tino_scale_speed(4, C->read, runtime, 1, -6)
	, C->currentpos, C->currentlen
	, tino_scale_slew_avg(5, 6, C->read, (unsigned long long)runtime, 1, -7)
	);
  fflush(C->state);

  return 0;
}

static int
md5at(CONF, unsigned long long from, unsigned long long count)
{
  int			got;
  unsigned long long	pos;
  tino_md5_ctx		ctx;

  if (tino_file_lseekE(C->fd, (tino_file_size_t)from, SEEK_SET)!=from)
    return 1+err(C, "seek error");

  C->lastio = from;

  tino_md5_init(&ctx);
  for (pos=0; pos<count; pos+=got)
    {
      unsigned long long	max;

      max	= count - pos;
      if (C->blocksize && max > C->blocksize)
	max	= C->blocksize;
      if ((got=tino_file_readE(C->fd, C->block, (size_t)max))<0)
        return 1+err(C, "read error at 0x%llx", pos);
      if (got==0)
        return 1+err(C, "unexpected EOF at 0x%llx", pos);
      tino_md5_update(&ctx, C->block, got);
      C->lastio	+= got;
      C->read	+= got;
    }
  tino_md5_hex(&ctx, (unsigned char *)C->digest);
  return 0;
}

static int
addstate(CONF, char state, unsigned long long from, unsigned long long count, const char *chksum, const char *comment)
{
  C->states++;

  if (C->relaxed && C->currentpos<from)
    addstate(C, '+', C->currentpos, from-C->currentpos, NULL, NULL);

  if (C->currentlen && (chksum || C->laststate!=state))
    {
      fprintf(C->out, "0x%llx 0x%llx %c\n", C->currentpos-C->currentlen, C->currentlen, C->laststate);
      C->currentlen = 0;
    }
  C->laststate = state;
  if (!state)
    return 0;

  if (C->currentpos != from)
    return err(C, "state sequence %llx(%llx) vs. %llx(%llx) broken (logfile corrupt?)", C->currentpos, C->currentlen, from, count);

  C->currentpos	+= count;
  C->currentlen	+= count;
  if (chksum)
    {
      /* C->currentlen	== count	*/
      fprintf(C->out, "0x%llx 0x%llx %c %s\n", from, count, state, chksum);
      C->currentlen	= 0;
    }
  if (comment)
    fprintf(C->out, "# 0x%llx 0x%llx + %s\n", from, count, comment);

  if (C->unbuffered)
    fflush(C->out);

  return 0;
}

static int
ddrescue_verify(CONF)
{
  int		txt;
  TINO_BUF	buf;
  const char	*line;

  if ((C->fd=tino_file_openE(C->name, O_RDONLY|(C->direct?O_DIRECT:0)))<0)
    {
      if (errno==EINVAL && C->direct) 
        tino_err("cannot open binary (hint: remove option -d): %s", C->name);
      else
        tino_err("cannot open binary: %s", C->name);
      return 1;
    }
  txt	= 0;
  if (strcmp(C->input, "-") && (txt=tino_file_open_readE(C->input))<0)
    {
      tino_err("%s: cannot open log", C->input);
      return 1;
    }

  tino_buf_initO(&buf);

  fprintf(C->out, "# img:  %s\n", C->name);
  fprintf(C->out, "# list: %s\n", C->input);
  if (C->cont)
    fprintf(C->out, "# from: 0x%llx\n", C->cont);
  else
    fprintf(C->out, "0x0 +\n");
  if (C->relaxed)
    fprintf(C->out, "# relaxed\n");
  if (C->direct)
    fprintf(C->out, "# direct\n");
  C->currentpos	= C->cont;
  C->currentlen	= 0;
  C->laststate	= 0;
  while ((line=tino_buf_line_read(&buf, txt, 10))!=0)
    {
      int	n;
      char	state;
      char	cmp[64];

      if (line[0]!='0')	/* Dirty, ignore any line which does not start with 0x..	*/
	continue;

      cmp[0]	= 0;
      C->cnt	= 0;
      n	= sscanf(line, "0x%llx 0x%llx %c %60s", &C->from, &C->cnt, &state, cmp);
      if (n<3)
	continue;
      if (C->from+C->cnt <= C->cont)
	continue;
      if (state!='+' || C->cnt < C->mincount)
	{
	  addstate(C, state, C->from, C->cnt, NULL, NULL);
	  continue;
        }
      if (!*cmp)	/* No checksum - it must be a ddrescue logfile	*/
	{
	  unsigned long long	part, len;

	  for (part=0; part<C->cnt; part+=len)
	    {
	      len	= C->cnt - part;
	      if (C->maxpart && len>C->maxpart)
		len	= C->maxpart;
	      if (C->from+part+len <= C->cont)
		continue;
              if (md5at(C, C->from+part, len))
	        return 1;
	      addstate(C, '+', C->from+part, len, C->digest, NULL);
	    }
	}
      else if (md5at(C, C->from, C->cnt))
	{
	  addstate(C, '-', C->from, C->cnt, NULL, NULL);
	  if (!C->ignore)
	    return 1;
	}
      else if (strcmp(cmp, C->digest))
	{
	  err(C, "md5sum mismatch: wanted=%s got=%s", cmp, C->digest);
	  addstate(C, '?', C->from, C->cnt, NULL, C->digest);
	}
      else
	addstate(C, '+', C->from, C->cnt, NULL, NULL);
    }
  if (tino_file_closeE(C->fd))
    tino_err("%s: cannot close", C->name);
  C->fd	= 0;
  addstate(C, 0, 0ull, 0ull, NULL, NULL);

  tino_buf_freeO(&buf);
  return 0;
}

static void
verror_fn(const char *pref, TINO_VA_LIST list, int err)
{
  errs	= 1;
  tino_verror_std(pref, list, err);
  errno = 0;
}

int
main(int argc, char **argv)
{
  int			argn;
  struct _config	config;
  CONF = &config;

  C->out		= stdout;
  C->state		= stderr;
  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 2, 2,
		      TINO_GETOPT_VERSION(DDRESCUE_VERIFY_VERSION)
		      " outfile logfile|-\n"
		      "	1) Create MD5 checksums of ddrescue outfile/logfile to verify that\n"
		      "	   the readable parts are correct, without transferring outfile again.\n"
		      "	2) Verify the checksums (given as logfile) and output a new logfile,\n"
		      "	   such that the errors can be corrected using ddrescue."
		      ,

		      TINO_GETOPT_USAGE
		      "h	this Help"
		      ,
		      TINO_GETOPT_ULONGINT
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "b size	Blocksize for IO"
		      , &C->blocksize,
		      (unsigned long)(BUFSIZ*10),
		      (unsigned long)(BUFSIZ),

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      "c pos	Continue from position (in case of interrupt)\n"
		      "		You can find the position in the output"
		      , &C->cont,

		      TINO_GETOPT_FLAG
		      "d	Direct IO"
		      , &C->direct,

		      TINO_GETOPT_FLAG
		      "i	Ignore common errors"
		      , &C->ignore,

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "m size	Max size of block for md5 (use 0 for unlimited)"
		      , &C->maxpart,
		      0x100000ull,
		      0ull,

		      TINO_GETOPT_FLAG
		      "q	Quiet (do not output progress)"
		      , &C->quiet,

		      TINO_GETOPT_FLAG
		      "r	Relaxed reading of input\n"
		      "		The input log can have holes, which are silently output as '+'"
		      , &C->relaxed,

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "s size	Skip blocks of less size (use 0 to do not skip)"
		      , &C->mincount,
		      0x10000ull,
		      0ull,

		      TINO_GETOPT_FLAG
		      "u	Unbuffered output"
		      , &C->unbuffered,

		      NULL);

  if (argn<=0)
    return 1;

  C->block	= tino_alloc_alignedO(C->blocksize);

  C->name	= argv[argn];
  C->input	= argv[argn+1];

  C->states	= 0;
  C->lastio	= 0;
  C->currentpos	= 0;
  C->read	= 0;
  tino_alarm_set(1, progress, C);

  ddrescue_verify(C);

  tino_freeO(C->block);
  return errs;
}

