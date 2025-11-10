#include <windows.h>
#include "misc.h"

#pragma pack(1)
struct patch_t
{
    BYTE nPatchType; // OP code, 0xE9 for JMP
    DWORD dwAddress;
};
#pragma pack()

BOOL apply_patch(BYTE eType, SIZE_T dwAddress, const void *pTarget, SIZE_T *orig_size, BYTE *replaced)
{
    DWORD oldProtect, tempProtect;
    struct patch_t pWrite = {
        eType,
        (DWORD)((SIZE_T)pTarget - (dwAddress + sizeof(DWORD) + sizeof(BYTE)))
    };

    VirtualProtect((LPVOID)dwAddress, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect);
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)dwAddress, replaced, sizeof(pWrite), orig_size); // 5-й аргумент теперь SIZE_T*
    BOOL success = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &pWrite, sizeof(pWrite), NULL);
    VirtualProtect((LPVOID)dwAddress, sizeof(DWORD), oldProtect, &tempProtect);

    return success;
}

void exec_copy(SIZE_T addr, BYTE *replaced, SIZE_T orig_size)
{
    DWORD oldProtect, tempProtect;
    VirtualProtect((LPVOID)addr, orig_size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)addr, replaced, orig_size);
    VirtualProtect((LPVOID)addr, orig_size, oldProtect, &tempProtect);
}
