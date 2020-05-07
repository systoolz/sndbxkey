#include <stdio.h>
#include <windows.h>
#include "dlloader.h"

#include "sbhelper.h"

#define SB_FLAG_PRD0 0x70726430
#define SB_FLAG_SYSC 0x73797363

typedef DWORD (WINAPI *SBIEAPI_QUERYLICENSEPROC)(DWORD flag, void *data);
typedef DWORD (WINAPI *SBIEAPI_GETVERSIONPROC)(void *data);

#pragma pack(push, 1)
typedef struct {
  ULONG   size;
  sbx_key skey;
} bnumskey;

typedef struct {
  HINSTANCE hLibrary;
  SBIEAPI_QUERYLICENSEPROC SbieApi_QueryLicense;
  SBIEAPI_GETVERSIONPROC SbieApi_GetVersion;
} SBIEDPTR;
#pragma pack(pop)

static CCHAR stSBIEDLL[] =
  "SbieDll.dll\0"
  "_SbieApi_QueryLicense@8\0"
  "_SbieApi_GetVersion@4\0";

void SBFillStruct(sbx_key *sbk) {
SBIEDPTR *sbp;
WCHAR ver[64];
size_t i;
  /* load library file */
  ZeroMemory(sbk, sizeof(sbk[0]));
  sbp = (SBIEDPTR *) LoadDLLFile(stSBIEDLL, sizeof(sbp[0]));
  if (sbp) {
    /* get Version Number */
    sbk->flags_1 |= (!sbp->SbieApi_GetVersion(&ver)) ? 1 : 0;
    /* get Product Key */
    for (i = 0; i < 4; i++) {
      if (sbp->SbieApi_QueryLicense(SB_FLAG_PRD0 + i, &sbk->prodkey[i * 8])) {
        break;
      }
    }
    sbk->flags_1 |= (i >= 4) ? 2 : 0;
    /* get System Sode */
    sbk->flags_1 |= (!sbp->SbieApi_QueryLicense(SB_FLAG_SYSC, &sbk->syscode)) ? 4 : 0;
    /* everything fine */
    if (sbk->flags_1 == (1 | 2 | 4)) {
      /* init version string */
      for (i = 0; i < 12; i++) {
        sbk->version[i] = '_';
      }
      /* copy version string */
      for (i = 0; i < 12; i++) {
        if (!ver[i]) { break; }
        sbk->version[i] = ver[i];
      }
      /* init flags */
      sbk->flags_1 = (GetTickCount() << 8) | 0x01;
      sbk->flags_2 = 0x80000001;
      sbk->flags_3 = 1;
      /* init padding */
      for (i = 0; i < 164; i++) {
        Sleep(20); /* make sure GetTickCount will return different values */
        sbk->padding[i] = GetTickCount();
      }
      /* add CRC */
      sbk->crcat64 = CRC_AdlerTzuk64((UCHAR *) &sbk->flags_2, sizeof(sbk[0]) - (4 * 4));
    } else {
      /* error */
      ZeroMemory(sbk, sizeof(sbk[0]));
    }
    FreeDLLFile(sbp, sizeof(sbp[0]));
  }
}

void WaitForAnyKey(void) {
DWORD data, dw;
  ReadFile(GetStdHandle(STD_INPUT_HANDLE), &data, 4, &dw, NULL);
}

int main(void) {
bnumskey sbk;
WCHAR *wkey;
size_t i;
  printf(
    "Sandboxie Activation Key generator v1.0 [unfinished]\n"
    "(c) SysTools 2020\n"
    "http://systools.losthost.org/?misc\n\n"
    "Tested only with Sandboxie 5.22.\n\n"
  );
  printf("Trying to load SbieDll.dll and obtain required information...");
  SBFillStruct(&sbk.skey);
  if (sbk.skey.flags_1) {
    /* bignum length */
    sbk.size = sizeof(sbk.skey) / 4;
    printf("ok\n\n");
    wkey = BigNum_ConvertToString(NULL, (BIGNUM) &sbk, 36);
    if (wkey) {
      printf(
        "MISSING STEP:\n\n"
        "Here must be an encryption part for the Sandboxie Activation Key generation.\n"
        "But it requires private 2048 bit RSA key which Sophos refusing to release.\n"
        "Because of that string below WILL NOT WORK as actual activation key.\n\n"
        "Yes, Sandboxie Open Source tool now, but older version which has less bugs and\n"
        "Windows XP support require activation for work with the license.\n\n"
        "If you're legal Sandboxie license owner - contact Sophos and demand this RSA\n"
        "key or the activation tool to be released! You paid for this software and you\n"
        "have all the rights to use it even after discontinuance.\n\n"
        "Press ENTER to contunue..."
      );
      WaitForAnyKey();
      printf("\n\n");
      /* lazy Unicode to ANSI conversion */
      for (i = 0; wkey[i]; i++) {
        printf("%c", wkey[i]);
      }
      printf("\n\n");
      Pool_Free(wkey, 0);
    }
  } else {
    printf("error!\nRun this tool from the Sandboxie folder or drop a SbieDll.dll file here.\n\n");
  }
  printf("Press ENTER to exit...");
  WaitForAnyKey();
  printf("\n\n");
  return(0);
}
