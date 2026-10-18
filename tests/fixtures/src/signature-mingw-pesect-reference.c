/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>

WINBOOL _ValidateImageBase(PBYTE);
PIMAGE_SECTION_HEADER _FindPESection(PBYTE, DWORD_PTR);
PIMAGE_SECTION_HEADER _FindPESectionByName(const char *);
PBYTE _GetPEImageBase(void);
int __mingw_GetSectionCount(void);

int main(void) {
    PBYTE base = _GetPEImageBase();
    PIMAGE_SECTION_HEADER text = _FindPESectionByName(".text");
    int count = __mingw_GetSectionCount();
    if (base == NULL)
        return 1;
    if (text != NULL)
        count += _FindPESection(base, text->VirtualAddress) != NULL;
    return count + _ValidateImageBase(base);
}
