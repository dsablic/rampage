/* Link-time stand-ins for the capture and network libraries privacy.c calls: each LIB_* build is a shared library
 * with the real library's soname, so the program imports these functions by name. Never run. */
#if defined(LIB_ASOUND)
int snd_pcm_open(void **pcm, const char *name, int stream, int mode) { return -1; }
long snd_pcm_readi(void *pcm, void *buffer, unsigned long frames) { return -1; }
long snd_pcm_writei(void *pcm, const void *buffer, unsigned long frames) { return -1; }
int snd_pcm_close(void *pcm) { return 0; }
#elif defined(LIB_TINYALSA)
void *pcm_open(unsigned int card, unsigned int device, unsigned int flags, const void *config) { return 0; }
int pcm_read(void *pcm, void *data, unsigned int count) { return -1; }
int pcm_close(void *pcm) { return 0; }
#elif defined(LIB_PULSE_SIMPLE)
void *pa_simple_new(const char *server, const char *name, int dir, const char *dev, const char *stream_name,
                    const void *ss, const void *map, const void *attr, int *error) { return 0; }
int pa_simple_read(void *s, void *data, unsigned long bytes, int *error) { return -1; }
#elif defined(LIB_CURL)
void *curl_easy_init(void) { return 0; }
int curl_easy_setopt(void *curl, int option, ...) { return 0; }
int curl_easy_perform(void *curl) { return 0; }
#elif defined(LIB_MOSQUITTO)
int mosquitto_connect(void *mosq, const char *host, int port, int keepalive) { return 0; }
int mosquitto_publish(void *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos,
                      int retain) { return 0; }
#endif
