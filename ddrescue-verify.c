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

static int			unbuffered;

static tino_md5_ctx		ctx;

static int			errs;
static FILE			*out;
static unsigned long		blocksize;
static unsigned long long	maxpart;
static unsigned long long	mincount;

static int
md5at(FILE *fd, const char *name, unsigned long long from, unsigned long long cnt, char *sum)
{
  static void		*block;
  int			got;
  unsigned long long	pos;

  if (!block)
    block	= tino_allocO(blocksize);
  tino_md5_init(&ctx);


  if (tino_file_fseekE(fd, (tino_file_size_t)from, SEEK_SET))
    {
      tino_err("seek error to %llu: %s", from, name);
      return 1;
    }
  for (pos=0; pos<cnt && (got=fread(block, (size_t)1, (size_t)((cnt-pos)>blocksize ? blocksize : (size_t)(cnt-pos)), fd))>0; pos+=got)
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
      if (n<3 || state!='+' || count<mincount)
	continue;
      if (!*cmp)
	{
	  unsigned long long	part, len;

	  for (part=0; part<count; part+=len)
	    {
	      len = (maxpart && count-part>maxpart) ? maxpart : count-part;
              if (md5at(bin, img, from+part, len, chksum))
	        return;
	      fprintf(out, "0x%llx 0x%llx %c %s\n", from+part, len, state, chksum);
	      if (unbuffered)
		fflush(out);
	    }
	}
      else if (md5at(bin, img, from, count, chksum))
	return;
      else if (strcmp(cmp, chksum))
	{
	  tino_err("block at %llu: md5sum mismatch: wanted=%s got=%s", from, cmp, chksum);
	  fprintf(out, "0x%llx 0x%llx %c %s\n", from, count, state, chksum);
	}
      else
	{
	  fprintf(stderr, ".");
	  fflush(stderr);
	}
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

  out			= stdout;
  tino_verror_fn	= verror_fn;
  argn	= tino_getopt(argc, argv, 2, 2,
		      TINO_GETOPT_VERSION(DDRESCUE_VERIFY_VERSION)
		      " drive.img drive.log"
		      ,

		      TINO_GETOPT_USAGE
		      "h	this help"
		      ,
		      TINO_GETOPT_ULONGINT
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "b size	Blocksize for operation"
		      , &blocksize,
		      (unsigned long)(BUFSIZ*10),
		      (unsigned long)(BUFSIZ),

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "m size	Max size of block for md5 (use 0 for unlimited)"
		      , &maxpart,
		      0x10000000ull,
		      0ull,

		      TINO_GETOPT_ULLONG
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MIN
		      "s size	Skip blocks of less size (use 0 to disable)"
		      , &mincount,
		      0x10000ull,
		      0ull,

		      TINO_GETOPT_FLAG
		      "u	Unbuffered output"
		      , &unbuffered,

		      NULL);

  if (argn<=0)
    return 1;

  ddrescue_verify(argv[argn], argv[argn+1]);

  return errs;
}
