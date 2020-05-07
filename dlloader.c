#include "dlloader.h"

#pragma pack(push, 1)
typedef struct {
  HINSTANCE hLibrary;
  FARPROC  *ProcList;
} LOADHEAD;
#pragma pack(pop)

void *LoadDLLFile(CCHAR *s, size_t l) {
LOADHEAD *p;
FARPROC *a;
  p = NULL;
  if ((s) && (l >= sizeof(LOADHEAD))) {
    p = (LOADHEAD *) LocalAlloc(LPTR, l);
    if (p) {
      p->hLibrary = LoadLibraryA(s);
      if (p->hLibrary) {
        a = (FARPROC *) &p->ProcList;
        for(; *s; s++); s++;
        while (*s) {
          *a = GetProcAddress(p->hLibrary, s);
          a++;
          for(; *s; s++); s++;
        }
      } else {
        LocalFree(p);
        p = NULL;
      }
    }
  }
  return(p);
}

void FreeDLLFile(void *p, size_t l) {
  if ((p) && (l >= sizeof(LOADHEAD))) {
    if (((LOADHEAD *) p)->hLibrary) {
      FreeLibrary(((LOADHEAD *) p)->hLibrary);
    }
    ZeroMemory(p, l);
    LocalFree(p);
  }
}
