/* Create an MD5 file for quick ddrescue image verification
 *
 * This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 */

#define TINO_NEED_OLD_ERR_FN

#include "tino/fileerr.h"
#include "tino/buf_line.h"
#include "tino/getopt.h"
#include "tino/md5.h"

#include "ddrescue-verify_version.h"

static int		unbuffered;

static tino_md5_ctx	ctx;

static int		errs;
static FILE		*out;
static unsigned		blocksize;

#if 0
  tino_md5_init(&ctx);
  while ((got=fread(block, (size_t)1, (size_t)blk, fd))>0)
    {
      tino_md5_update(&ctx, block, got);
      len += got;
    }
#endif

static int
md5at(FILE *fd, const char *name, unsigned long long from, unsigned long long cnt, char *sum)
{
  static void		*block;
  int			got;
  unsigned long long	pos;

  if (!block)
    block	= tino_allocO(blocksize);
  tino_md5_init(&ctx);


  if (tino_file_fseekE(fd, (tino_file_size_t)from, SEEK_SET)!=from)
    {
      tino_err("seek error %llu: %s", from, name);
      return 1;
    }
  for (pos=0; pos<cnt && (got=fread(block, (size_t)1, (size_t)(cnt>blocksize ? blocksize : cnt), fd))>0; pos+=got)
    tino_md5_update(&ctx, block, got);
  if (pos != cnt)
    {
      tino_err("block at %llu: length mismatch: wanted=%llu got=%llu: %s", from, cnt, pos, name);
      return 1;
    }
  tino_md5_hex(&ctx, (unsigned char *)sum);
  return 0;
}

static void
ddrescue_verify(const char *img, const char *list)
{
  FILE		*bin;
  int		txt;
  TINO_BUF	buf;
  const char	*line;

  tino_buf_initO(&buf);
  txt	= 0;
  if (strcmp(list, "-") && (txt=tino_file_open_readE(list))<0)
    {
      tino_err("cannot read text: %s", list);
      return;
    }
  if ((bin=fopen(img, "rb"))==NULL)
    {
      tino_err("cannot read binary: %s", img);
      return;
    }

  fprintf(out, "# img:  %s\n", img);
  fprintf(out, "# list: %s\n", list);

  while ((line=tino_buf_line_read(&buf, txt, 10))!=0)
    {
      unsigned long long	from, count;
      int			n;
      char			state;
      char			chksum[64], cmp[64];

      if (line[0]!='0')
	continue;
      cmp[0]	= 0;
      count	= 0;
      n	= sscanf(line, "0x%llx 0x%llx %c %60s", &from, &count, &state, cmp);
      if (n<3 || state!='+')
	continue;
      if (md5at(bin, img, from, count, chksum))
	break;
      if (!*cmp)
	fprintf(out, "0x%llx 0x%llx %c %s\n", from, count, state, chksum);
      else if (strcmp(cmp, chksum))
	tino_err("block at %llu: md5sum mismatch: wanted=%s got=%s", from, cmp, chksum);
      if (unbuffered)
	fflush(out);
    }
  if (ferror(bin))
    {
      tino_err("read error: %s", img);
      fclose(bin);
      return;
    }
  if (fclose(bin))
    {
      tino_err("cannot close: %s", img);
      return;
    }
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
  int		argn;

  unbuffered		= 1;
  out			= stdout;
  blocksize		= BUFSIZ*10;
  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 2, 2,
		      TINO_GETOPT_VERSION(DDRESCUE_VERIFY_VERSION)
		      " drive.img drive.log\n"
		      "\t"
		      ,

		      TINO_GETOPT_USAGE
		      "h	this help"
		      ,
#if 0
		      TINO_GETOPT_UNSIGNED
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_SUFFIX
		      "b size	Blocksize for operation"
		      , &blocksize,
		      (unsigned)(BUFSIZ*10),

		      TINO_GETOPT_FLAG
		      "c	Cat mode, echo input to stdout again\n"
		      "		sends MD5 sum to stderr, use -u to use 2>&1"
		      , &cat,

		      TINO_GETOPT_FLAG
		      "d	Do md5sum of commandline args or lines from stdin"
		      , &direct,

		      TINO_GETOPT_FLAG
		      "i	Ignore errors silently"
		      , &ignore,

		      TINO_GETOPT_FLAG
		      "k	prefix MD5 with blocKnumbers.  Implies -m\n"
		      "		This way equal blocks give different hashes."
		      , &blocknumber,

		      TINO_GETOPT_FLAG
		      "l	overLapping mode for -m (-m defaults to 1 MiB)\n"
		      "		Outputs 1-12-23-34+4=1234 (triple effort).\n"
		      "		The partial HASHes overlap by 1 block of size -m"
		      , &overlap,

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      "m size	Max size of block for md5 (default: unlimited)\n"
		      "		One MD5 sum each size bytes (and one for all).\n"
		      "		Outputs 1+2+3+4=1234. (double effort)"
		      , &maxsize,

		      TINO_GETOPT_FLAG
		      "n	read NUL terminated lines\n"
		      "		Note that NUL always acts as line terminator."
		      , &nflag,

		      TINO_GETOPT_STRING
		      "p str	Preset md5 algorithm with given string\n"
		      "		This modifies the md5 algorithm by prefixing str."
		      , &prefix,

		      TINO_GETOPT_FLAG
		      "q	Quiet mode: do not print (shell escaped) file names"
		      , &quiet,

		      TINO_GETOPT_FLAG
		      "s	read data from Stdin instead, not a file list\n"
		      "		Enables '-' as file argument for stdin, too."
		      , &stdinflag,

		      TINO_GETOPT_CHAR
		      "t	line Termination character, default whitespace\n"
		      "		Note: -t defaults to NUL if -n present."
		      , &tchar,

		      TINO_GETOPT_FLAG
		      "u	Unbuffered output"
		      , &unbuffered,

		      TINO_GETOPT_FLAG
		      "z	Write NUL(\"zero\") terminated lines, disables shell escape"
		      , &zero,
#endif
		      NULL);

  if (argn<=0)
    return 1;

  ddrescue_verify(argv[argn], argv[argn+1]);

  return errs;
}
