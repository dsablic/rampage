/* The native library of the Android fixtures (recorder.apk): the JNI export the sample's `native` method
 * Capture.nativeEncode([B)I binds to by name, and a JNI_OnLoad. No headers: the JNI types are spelled out. */
typedef int jint;
typedef void *JNIEnv;
typedef void *jobject;
typedef void *jbyteArray;
typedef void *JavaVM;

jint Java_com_example_recorder_Capture_nativeEncode(JNIEnv *env, jobject self, jbyteArray data) {
    (void)env;
    (void)self;
    return data ? 1 : 0;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return 0x00010006;
}
