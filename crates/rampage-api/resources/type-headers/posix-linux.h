/* Adapted from musl v1.2.5; Linux ABI only. See provenance.json and LICENSE.musl. */
typedef uint2 sa_family_t;
struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};
