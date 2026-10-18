/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>

WINBOOL _ValidateImageBase(PBYTE);
PIMAGE_SECTION_HEADER __mingw_GetSectionForAddress(LPVOID);
PIMAGE_SECTION_HEADER _FindPESectionExec(size_t);
PBYTE _GetPEImageBase(void);
WINBOOL _IsNonwritableInCurrentImage(PBYTE);
const char *__mingw_enum_import_library_names(int);

int main(void) {
    static const char message[] = "target in-memory section checks";
    PBYTE base = _GetPEImageBase();
    PIMAGE_SECTION_HEADER executable = _FindPESectionExec(0);
    const char *imports = __mingw_enum_import_library_names(0);
    if (base == NULL)
        return 2;
    return _ValidateImageBase(base) + (executable != NULL) + (imports != NULL) +
           _IsNonwritableInCurrentImage((PBYTE)message) +
           (__mingw_GetSectionForAddress((LPVOID)message) != NULL);
}
