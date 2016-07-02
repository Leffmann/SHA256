//  SHA256 v1.2

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <exec/types.h>
#include <dos/dos.h>
#include <dos/dosasl.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>

#define _STR(x) #x
#define STR(x) _STR(x)

const char version[] = "$VER: SHA256 1.2 " __AMIGADATE__ " Robert Leffmann";

static const int BUFSIZE = 64*1024;    //  Must be a multiple of 64
static UBYTE* buffer;

void SHA256Acc(const void* buffer, ULONG* hash, ULONG count);
static int CalcHash(BPTR file, ULONG* hash);
static void PrintHash(const ULONG* hash);
static int ProcessFile(STRPTR name);



int main(int nargs, const char** args) {

  if (nargs == 2  &&  strcmp(args[1], "?") == 0) {
    puts("SHA256 1.2 " __DATE__ "\n"
         "Usage: sha256 [files]\n"
         "Wildcards are allowed in the filenames.\n"
         "The standard input will be used when no files are specified.");
    return RETURN_OK;
  }

  buffer = AllocVec(BUFSIZE+64, MEMF_ANY);
  if (!buffer) {
    fputs("Could not get " STR(BUFSIZE) " bytes for input buffer.", stderr);
    return RETURN_ERROR;
  }

  //  Process the standard input if no files were specified

  int err;
  if (nargs == 1) {
    ULONG hash[8];
    CalcHash(Input(), hash);
    PrintHash(hash);
    puts("");
    err = RETURN_OK;

  } else {

    //  Process all arguments

    struct AnchorPath* ap = AllocVec(sizeof (struct AnchorPath)+500, MEMF_ANY|MEMF_CLEAR);
    if (!ap) {
      FreeVec(buffer);
      return RETURN_ERROR;
    }

    struct Process* proc = (void*)FindTask(NULL);
    APTR oldwinptr = proc->pr_WindowPtr;
    proc->pr_WindowPtr = (APTR)-1;

    err = RETURN_OK;
    for (int i = 1; i < nargs; ++i) {

      //  Find and process all files that match the current argument

      ap->ap_BreakBits = 0;
      ap->ap_Strlen = 500;
      int exerr = MatchFirst(args[i], ap);

      while (exerr == 0) {
        if (ap->ap_Info.fib_DirEntryType < 0) {
          int ret = ProcessFile(ap->ap_Buf);
          if (ret > err)    err = ret;
        }

        exerr = MatchNext(ap);
      }

      MatchEnd(ap);
    }

    proc->pr_WindowPtr = oldwinptr;
    FreeVec(ap);
  }

  FreeVec(buffer);
  return err;
}



static int ProcessFile(STRPTR name) {
  BPTR file = Open(name, MODE_OLDFILE);
  if (!file) {
    fprintf(stderr, "* could not open file: %s\n", name);
    return RETURN_WARN;
  }

  ULONG hash[8];
  if (CalcHash(file, hash) == -1) {
    fprintf(stderr, "* read error: %s\n", name);
    Close(file);
    return RETURN_WARN;
  }

  PrintHash(hash);
  printf("  %s\n", name);

  Close(file);
  return RETURN_OK;
}



static int CalcHash(BPTR file, ULONG* hash) {
  hash[0] = 0x6a09e667;  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;  hash[7] = 0x5be0cd19;

  //  Process the file in chunks of 'BUFSIZE' bytes at a time

  ULONG lastlen, filelen = 0;
  ULONG remaining = BUFSIZE;
  do {
    lastlen = Read(file, buffer, remaining);
    if (lastlen == (ULONG)-1)    return -1;

    remaining -= lastlen;
    filelen += lastlen;

    if (remaining == 0) {
      SHA256Acc(buffer, hash, BUFSIZE/64);
      remaining = BUFSIZE;
    }
  } while (lastlen > 0);

  //  Append terminating 1-bit, padding, and message size

  lastlen = BUFSIZE-remaining;
  buffer[lastlen] = 0x80;
  ULONG padlen = (64-9+BUFSIZE-lastlen)%64;
  ULONG* pmsglen = (ULONG*)(buffer+lastlen+padlen+1);
  memset(buffer+lastlen+1, 0, padlen);
  pmsglen[0] = filelen>>29;
  pmsglen[1] = filelen<<3;

  SHA256Acc(buffer, hash, (lastlen+padlen+9)/64);

  return 0;
}



static void PrintHash(const ULONG* hash) {
  printf("%08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx",
         hash[0], hash[1], hash[2], hash[3],
         hash[4], hash[5], hash[6], hash[7]);
}
