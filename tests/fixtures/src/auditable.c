/* A stand-in for a cargo-auditable binary: its `.dep-v0` section holds zlib-compressed dependency JSON, generated
 * from auditable.json into auditable-data.h by build-buildinfo.sh. */
#include "auditable-data.h"

#ifdef __APPLE__
#define DEP_SECTION "__DATA,.dep-v0"
#else
#define DEP_SECTION ".dep-v0"
#endif

__attribute__((used, section(DEP_SECTION))) const unsigned char dep_v0[] = { AUDITABLE_DATA };

int main(void) {
    return ((volatile const unsigned char *)dep_v0)[0] == 0x78 ? 0 : 1;
}
