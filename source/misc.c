#include <windows.h>
#include "misc.h"

#pragma pack(1)
struct patch_t
{
    BYTE nPatchType;
    SIZE_T dwAddress;
};
#pragma pack()

BOOL apply_patch(BYTE eType, SIZE_T dwAddress, const void *pTarget, SIZE_T *orig_size, BYTE *replaced)
{
    SIZE_T dwOldValue, dwTemp;
    struct patch_t pWrite =
    {
        eType,
        (SIZE_T)pTarget - (dwAddress + sizeof(SIZE_T) + sizeof(BYTE))
    };

    VirtualProtect((LPVOID)dwAddress, sizeof(struct patch_t), PAGE_EXECUTE_READWRITE, (PDWORD)&dwOldValue);
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)dwAddress, (LPVOID)replaced, sizeof(pWrite), orig_size);
    BOOL bSuccess = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &pWrite, sizeof(pWrite), NULL);
    VirtualProtect((LPVOID)dwAddress, sizeof(struct patch_t), dwOldValue, &dwTemp);

    return bSuccess;
}

inline void exec_copy(SIZE_T addr, BYTE *replaced, SIZE_T orig_size)
{
    SIZE_T old_val, temp;
    VirtualProtect((LPVOID)addr, orig_size, PAGE_EXECUTE_READWRITE, (PDWORD)&old_val);
    memcpy((void*)addr, replaced, orig_size);
    VirtualProtect((LPVOID)addr, orig_size, old_val, &temp);
}
