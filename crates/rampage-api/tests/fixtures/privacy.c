/* Capture and send paths for privacy_surface tests: an always-on microphone loop that uploads over HTTP, a camera
 * frame grabbed from a timer and written to a file, a microphone opened on a network command and published over
 * MQTT, push-to-talk recording behind an input-device read (in a caller, in the same function, and in a sibling
 * call), a capture also bound to a key through a handler table, one past the call-graph walk's bound, a local
 * (AF_UNIX) status message and a sysfs LED write that are not sinks, and a decoy that only plays a chime (a playback
 * stream, not capture). The capture and network libraries are declared here and provided by stub shared libraries at link
 * time (see build.sh), so every call is a real import. Every name is reserved (RFC 2606); the tests only analyze
 * the compiled program, they never run it. */
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <linux/videodev2.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ALSA (libasound), declared as in <alsa/asoundlib.h>. */
typedef struct snd_pcm snd_pcm_t;
enum { SND_PCM_STREAM_PLAYBACK = 0, SND_PCM_STREAM_CAPTURE = 1 };
int snd_pcm_open(snd_pcm_t **pcm, const char *name, int stream, int mode);
long snd_pcm_readi(snd_pcm_t *pcm, void *buffer, unsigned long frames);
long snd_pcm_writei(snd_pcm_t *pcm, const void *buffer, unsigned long frames);
int snd_pcm_close(snd_pcm_t *pcm);

/* tinyalsa, as in <tinyalsa/asoundlib.h>. */
struct pcm;
struct pcm_config;
#define PCM_IN 0x10000000
struct pcm *pcm_open(unsigned int card, unsigned int device, unsigned int flags, const struct pcm_config *config);
int pcm_read(struct pcm *pcm, void *data, unsigned int count);
int pcm_close(struct pcm *pcm);

/* PulseAudio simple API. */
typedef struct pa_simple pa_simple;
enum { PA_STREAM_PLAYBACK = 1, PA_STREAM_RECORD = 2 };
pa_simple *pa_simple_new(const char *server, const char *name, int dir, const char *dev, const char *stream_name,
                         const void *ss, const void *map, const void *attr, int *error);
int pa_simple_read(pa_simple *s, void *data, unsigned long bytes, int *error);

/* libcurl. */
typedef void CURL;
CURL *curl_easy_init(void);
int curl_easy_setopt(CURL *curl, int option, ...);
int curl_easy_perform(CURL *curl);
#define CURLOPT_URL 10002
#define CURLOPT_POSTFIELDS 10015

/* libmosquitto. */
struct mosquitto;
int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive);
int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload,
                      int qos, int retain);

static unsigned char audio[4096];
static unsigned char frame[8192];
static struct mosquitto *broker;
static volatile int running = 1;

__attribute__((noinline)) static void upload_chunk(const unsigned char *data, int length) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://ingest.vendor-cloud.example/v1/audio");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_perform(curl);
    (void)length;
}

/* A local status message: an AF_UNIX socket is IPC on the device, not a network send. */
__attribute__((noinline)) static void notify_daemon(void) {
    int local = socket(AF_UNIX, SOCK_DGRAM, 0);
    send(local, "recording", 9, 0);
    close(local);
}

/* Always on: started from main, no user input on the way. It also lights an LED through sysfs, which is a device
 * write, not a file sink. */
__attribute__((noinline)) static void record_loop(void) {
    snd_pcm_t *pcm;
    if (snd_pcm_open(&pcm, "hw:0,0", SND_PCM_STREAM_CAPTURE, 0) < 0)
        return;
    FILE *led = fopen("/sys/class/leds/mic/brightness", "w");
    if (led)
        fputs("1", led);
    notify_daemon();
    while (running) {
        snd_pcm_readi(pcm, audio, sizeof audio / 4);
        upload_chunk(audio, sizeof audio);
    }
    snd_pcm_close(pcm);
}

/* A camera frame, grabbed from a timer signal and kept in a file. */
__attribute__((noinline)) static void grab_frame(void) {
    int fd = open("/dev/video0", O_RDWR);
    if (fd < 0)
        return;
    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    struct v4l2_buffer buffer;
    memset(&buffer, 0, sizeof buffer);
    ioctl(fd, VIDIOC_STREAMON, &type);
    ioctl(fd, VIDIOC_DQBUF, &buffer);
    read(fd, frame, sizeof frame);
    FILE *out = fopen("/tmp/frame.raw", "wb");
    if (out) {
        fwrite(frame, 1, sizeof frame, out);
        fclose(out);
    }
    close(fd);
}

__attribute__((noinline)) static void on_timer(int signal_number) {
    (void)signal_number;
    grab_frame();
}

__attribute__((noinline)) static void start_timer(void) {
    struct itimerval every = {{60, 0}, {60, 0}};
    signal(SIGALRM, on_timer);
    setitimer(ITIMER_REAL, &every, 0);
}

/* The microphone, opened when a network peer asks. */
__attribute__((noinline)) static void listen_on_request(void) {
    struct pcm *pcm = pcm_open(0, 0, PCM_IN, 0);
    if (!pcm)
        return;
    pcm_read(pcm, audio, sizeof audio);
    mosquitto_publish(broker, 0, "devices/upstream/audio", sizeof audio, audio, 1, 0);
    pcm_close(pcm);
}

__attribute__((noinline)) static void *command_server(void *argument) {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    (void)argument;
    mosquitto_connect(broker, "mqtt.vendor-cloud.example", 8883, 60);
    for (;;) {
        int client = accept(server, 0, 0);
        char command[16];
        if (recv(client, command, sizeof command, 0) > 0 && command[0] == 'L')
            listen_on_request();
        close(client);
    }
    return 0;
}

/* Decoy: plays a chime. A playback stream is not capture. */
__attribute__((noinline)) static void play_chime(void) {
    snd_pcm_t *pcm;
    if (snd_pcm_open(&pcm, "default", SND_PCM_STREAM_PLAYBACK, 0) < 0)
        return;
    snd_pcm_writei(pcm, audio, sizeof audio / 4);
    snd_pcm_close(pcm);
}

/* A voice assistant started from main and also bound to a key through a table of handlers: its callers through
 * the table are not followed, so it is not said to lack a user trigger. */
__attribute__((noinline)) static void start_assistant(void) {
    snd_pcm_t *pcm;
    if (snd_pcm_open(&pcm, "hw:0,1", SND_PCM_STREAM_CAPTURE, 0) < 0)
        return;
    snd_pcm_readi(pcm, audio, 64);
}

static void (*const key_actions[])(void) = {play_chime, start_assistant};

/* Push to talk: recording follows a key press read from an input device. */
__attribute__((noinline)) static void record_while_pressed(void) {
    int error;
    pa_simple *stream = pa_simple_new(0, "talk", PA_STREAM_RECORD, 0, "voice", 0, 0, 0, &error);
    if (stream)
        pa_simple_read(stream, audio, sizeof audio, &error);
}

__attribute__((noinline)) static void button_loop(void) {
    int fd = open("/dev/input/event1", O_RDONLY);
    struct input_event event;
    if (fd < 0)
        return;
    ioctl(fd, EVIOCGRAB, 1);
    while (read(fd, &event, sizeof event) == sizeof event) {
        if (event.type == EV_KEY && event.value == 1)
            record_while_pressed();
        key_actions[event.code & 1]();
    }
}

/* Push to talk in one function: the key is read, then the microphone opened. */
__attribute__((noinline)) static void talk_on_key(void) {
    int fd = open("/dev/input/event3", O_RDONLY);
    struct input_event event;
    snd_pcm_t *pcm;
    if (fd < 0)
        return;
    ioctl(fd, EVIOCGRAB, 1);
    if (read(fd, &event, sizeof event) == sizeof event && event.value == 1 &&
        snd_pcm_open(&pcm, "hw:0,2", SND_PCM_STREAM_CAPTURE, 0) == 0)
        snd_pcm_readi(pcm, audio, 128);
}

__attribute__((noinline)) static void start_ui(void) {
    button_loop();
    talk_on_key();
}

/* A key read by a sibling: the loop records only after button_pressed reports a press. */
__attribute__((noinline)) static int button_pressed(void) {
    int fd = open("/dev/input/event2", O_RDONLY);
    struct input_event event;
    int pressed = fd >= 0 && read(fd, &event, sizeof event) == sizeof event && event.value == 1;
    close(fd);
    return pressed;
}

__attribute__((noinline)) static void record_clip(void) {
    snd_pcm_t *pcm;
    if (snd_pcm_open(&pcm, "hw:0,3", SND_PCM_STREAM_CAPTURE, 0) == 0)
        snd_pcm_readi(pcm, audio, 256);
}

__attribute__((noinline)) static void assistant_loop(void) {
    while (running)
        if (button_pressed())
            record_clip();
}

/* A capture eight calls below main, past the walk's bound: its trigger search is cut. The node name's direction
 * letter is filled in at run time, so the string alone says neither. */
__attribute__((noinline)) static void deep_capture(void) {
    char node[32];
    snd_pcm_t *pcm;
    snprintf(node, sizeof node, "/dev/snd/pcmC%uD%u%c", 0u, 0u, 'c');
    if (snd_pcm_open(&pcm, node, SND_PCM_STREAM_CAPTURE, 0) == 0)
        snd_pcm_readi(pcm, audio, 512);
}

__attribute__((noinline)) static void deep7(void) { deep_capture(); running += 7; }
__attribute__((noinline)) static void deep6(void) { deep7(); running += 6; }
__attribute__((noinline)) static void deep5(void) { deep6(); running += 5; }
__attribute__((noinline)) static void deep4(void) { deep5(); running += 4; }
__attribute__((noinline)) static void deep3(void) { deep4(); running += 3; }
__attribute__((noinline)) static void deep2(void) { deep3(); running += 2; }
__attribute__((noinline)) static void deep1(void) { deep2(); running += 1; }

int main(void) {
    pthread_t thread;
    play_chime();
    start_timer();
    start_assistant();
    deep1();
    pthread_create(&thread, 0, command_server, 0);
    if (fork() == 0)
        start_ui();
    if (fork() == 0)
        assistant_loop();
    record_loop();
    return 0;
}
