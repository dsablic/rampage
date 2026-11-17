/* The native library of the privacy fixture (watch.apk): the JNI export the `native` method Net.nativeSend([B)I
 * binds to by name, which opens an IPv4 socket, connects and sends. No headers: the types are spelled out and the
 * socket calls are left undefined, for the platform's libc to bind at load time. */
typedef int jint;
typedef void *JNIEnv;
typedef void *jobject;
typedef void *jbyteArray;

struct address {
    unsigned short family;
    unsigned short port;
    unsigned int ip;
    unsigned char zero[8];
};

extern int socket(int domain, int type, int protocol);
extern int connect(int fd, const void *address, unsigned int length);
extern long send(int fd, const void *data, unsigned long length, int flags);

jint Java_com_example_watch_Net_nativeSend(JNIEnv *env, jobject self, jbyteArray data) {
    (void)env;
    (void)self;
    struct address peer = {2, 0x5000, 0x0100000a, {0}};
    int fd = socket(2, 1, 0);
    if (fd < 0 || connect(fd, &peer, sizeof peer) != 0) {
        return -1;
    }
    return (jint)send(fd, data, 4, 0);
}
