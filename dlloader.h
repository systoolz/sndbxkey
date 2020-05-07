#ifndef __DLLOADER_H
#define __DLLOADER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void *LoadDLLFile(CCHAR *s, size_t l);
void FreeDLLFile(void *p, size_t l);

#ifdef __cplusplus
}
#endif

#endif
