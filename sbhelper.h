#ifndef __SBHELPER_H
#define __SBHELPER_H

/*
http://www.techhelpmanual.com/914-qbcd.html
BCD = Binary-Coded Decimal
-----------------------------------------------------
BCD is a way to represent decimal numbers in a more
compact way than ASCII text. One byte represents two
digits:
  01H = 1 decimal
  20H = 20 decimal (not 32)
  99H = 99 decimal (not 153)
-----------------------------------------------------
* BCD is used rarely on PCs and in PC programming.
* Note that hex digits A-F are never used, so numbers
  such as 0aH or b1H are invalid as BCD values.
*/
#pragma pack(push, 1)
typedef struct {
  ULONG   flags_1; /* (... & 0x0F) == 1 */
  ULONG64 crcat64; /* Tzuk32 CRC and Adler32 CRC */
  ULONG   flags_2; /* == 0x80000001 */
  ULONG   flags_3; /* == 1 */
  ULONG64 syscode; /* system code (hardware dependent) */
  BYTE    actilld; /* license activated till d/m/y in BCD format (00/00/0000 - till 31/12/2999) */
  BYTE    actillm;
  WORD    actilly;
  BYTE    lmtilld; /* license limited till d/m/y in BCD format (00/00/0000 - lifetime) */
  BYTE    lmtillm;
  WORD    lmtilly;
  CHAR    version[4+8]; /* == "5.22________" */
  CHAR    prodkey[32];  /* "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-1AAAV" */
  BYTE    padding[164];
} sbx_key;
#pragma pack(pop)

/* simply replaces for complicated original pool.c routines */
void *Pool_Alloc(void *pool, ULONG size) {
  return((void *) LocalAlloc(LPTR, size));
}

void Pool_Free(void *ptr, ULONG size) {
  if (ptr) { LocalFree(ptr); }
}

#include "bignum.h"
#define CRC_HEADER_ONLY
#include "crc.c"

#endif
