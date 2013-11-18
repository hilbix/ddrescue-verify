/* Create an MD5 file for quick ddrescue image verification
 *
 * This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 */

#define TINO_NEED_OLD_ERR_FN

#include "tino/buf_line.h"
#include "tino/getopt.h"
#include "tino/md5.h"

#include "ddrescue-verify_version.h"

static int	errs;

struct _config
  {
    int			unbuffered, ignore, direct;
    unsigned long	blocksize;
    unsigned long long	maxpart;
    unsigned long long	mincount;

    FILE		*out;
    const char		*name;
    int			fd;
    const char		*input;

    unsigned long long	from, cnt;

    void		*block;
    unsigned long long	pos;
    char		state;

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
  tino_err("%s at %llu(%llu): %s", C->name, C->from, C->cnt, errbuf);
  return 0;
}

static int
md5part(CONF, unsigned long long from, unsigned long long count)
{
  int			got;
  unsigned long long	pos;
  tino_md5_ctx		ctx;

  if (!C->block)
    C->block	= tino_alloc_alignedO(C->blocksize);

  if (tino_file_lseekE(C->fd, (tino_file_size_t)from, SEEK_SET)!=from)
    return 1+err(C, "seek error");

  tino_md5_init(&ctx);
  for (pos=0; pos<count; pos+=got)
    {
      unsigned long long	max;

      max	= count - pos;
      if (max > C->blocksize)
	max	= C->blocksize;
      if ((got=tino_file_readE(C->fd, C->block, max))<0)
        return 1+err(C, "read error at %llu", pos);
      if (got==0)
        return 1+err(C, "unexpected EOF at %llu", pos);
      tino_md5_update(&ctx, C->block, got);
    }
  tino_md5_hex(&ctx, (unsigned char *)C->digest);
  return 0;
}

static int
md5at(CONF, unsigned long long pos, unsigned long long count)
{
  int ret;

  ret = md5part(C, pos, count);
  fputc(ret ? 'x' : '.', stderr);
  fflush(stderr);
  return ret;
}

static void
addstate(CONF, char state, unsigned long long from, unsigned long long count, const char *chksum, const char *comment)
{
  if (!state)
    return;

  if (chksum)
    fprintf(C->out, "0x%llx 0x%llx %c %s\n", from, count, state, chksum);
  else
    fprintf(C->out, "0x%llx 0x%llx %c\n", from, count, state);
  if (comment)
    fprintf(C->out, "0x%llx 0x%llx %c %s\n", from, count, state, comment);

  if (C->unbuffered)
    fflush(C->out);
}

static int
ddrescue_verify(CONF)
{
  int			txt;
  TINO_BUF		buf;
  const char		*line;

  if ((C->fd=tino_file_openE(C->name, O_RDONLY|(C->direct?O_DIRECT:0)))<0)
    {
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
  fprintf(C->out, "0x0 +\n");
  C->pos	= 0;
  C->state	= 0;
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
}

int
main(int argc, char **argv)
{
  int			argn;
  struct _config	config;
  CONF = &config;

  C->out		= stdout;
  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 2, 2,
		      TINO_GETOPT_VERSION(DDRESCUE_VERIFY_VERSION)
		      " drive.img drive.log"
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

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "s size	Skip blocks of less size (use 0 to disable)"
		      , &C->mincount,
		      0x10000ull,
		      0ull,

		      TINO_GETOPT_FLAG
		      "u	Unbuffered output"
		      , &C->unbuffered,

		      NULL);

  if (argn<=0)
    return 1;

  C->name	= argv[argn];
  C->input	= argv[argn+1];
  ddrescue_verify(C);

  return errs;
}

