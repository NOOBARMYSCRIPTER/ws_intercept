#include <windows.h>
#include "misc.h"

#pragma pack(1)
struct patch_t
{
    BYTE nPatchType;
    SIZE_T dwAddress;
};
#pragma pack()

BOOL apply_patch(BYTE eType, DWORD64 dwAddress, const void *pTarget, DWORD *orig_size, BYTE *replaced)
{
    DWORD dwOldValue, dwTemp;
    struct patch_t pWrite =
    {
        eType,
        (DWORD)((uintptr_t)pTarget - (dwAddress + sizeof(DWORD) + sizeof(BYTE)))
    };

    VirtualProtect((LPVOID)dwAddress, sizeof(struct patch_t), PAGE_EXECUTE_READWRITE, &dwOldValue);
    ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, (LPVOID)replaced, sizeof(pWrite), (PDWORD)orig_size);
    BOOL bSuccess = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &pWrite, sizeof(pWrite), NULL);
    VirtualProtect((LPVOID)dwAddress, sizeof(struct patch_t), dwOldValue, &dwTemp);

    return bSuccess;
}

inline void exec_copy(DWORD64 addr, BYTE *replaced, DWORD orig_size)
{
    DWORD old_val, temp;
    VirtualProtect((LPVOID)addr, (SIZE_T)orig_size, PAGE_EXECUTE_READWRITE, &old_val);
    memcpy((void*)addr, replaced, orig_size);
    VirtualProtect((LPVOID)addr, (SIZE_T)orig_size, old_val, &temp);
}
