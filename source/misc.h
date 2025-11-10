#ifndef MISC_H
#define MISC_H

#include <windows.h>

BOOL apply_patch(BYTE eType, SIZE_T dwAddress, const void *pTarget, SIZE_T *orig_size, BYTE *replaced);
void exec_copy(SIZE_T addr, BYTE *replaced, SIZE_T orig_size);

#endif
