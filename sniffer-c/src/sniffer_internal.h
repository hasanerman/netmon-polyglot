#ifndef SNIFFER_INTERNAL_H
#define SNIFFER_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>

#include "sniffer.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
typedef volatile LONG sniffer_flag;
typedef HANDLE sniffer_thread;
#else
#include <pthread.h>
typedef volatile int sniffer_flag;
typedef pthread_t sniffer_thread;
#endif

#define NP_ERRBUF_SIZE 256
#define NP_READ_TIMEOUT_MS 100
#define REPLAY_MAX_RECORD 262144u

typedef struct np_pcap np_pcap;

struct np_timeval {
    long tv_sec;
    long tv_usec;
};

struct np_pkthdr {
    struct np_timeval ts;
    uint32_t caplen;
    uint32_t len;
};

struct np_if {
    struct np_if *next;
    char *name;
    char *description;
    void *addresses;
    uint32_t flags;
};

struct np_stat {
    unsigned int ps_recv;
    unsigned int ps_drop;
    unsigned int ps_ifdrop;
    unsigned int reserved[4];
};

struct pcap_api {
    void *lib;
    np_pcap *(*open_live)(const char *dev, int snaplen, int promisc, int to_ms, char *errbuf);
    int (*next_ex)(np_pcap *p, struct np_pkthdr **hdr, const uint8_t **data);
    void (*close)(np_pcap *p);
    int (*datalink)(np_pcap *p);
    char *(*geterr)(np_pcap *p);
    int (*stats)(np_pcap *p, struct np_stat *ps);
    void (*breakloop)(np_pcap *p);
    int (*findalldevs)(struct np_if **devs, char *errbuf);
    void (*freealldevs)(struct np_if *devs);
};

enum source_kind { SOURCE_LIVE, SOURCE_FILE };
enum run_state { STATE_IDLE, STATE_RUNNING, STATE_FINISHED };

struct sniffer {
    enum source_kind kind;
    enum run_state state;
    sniffer_flag stop_requested;
    sniffer_flag finished;
    sniffer_callback callback;
    void *user;
    int link_type;
    int realtime;
    uint64_t delivered;
    char err[SNIFFER_ERRBUF_LEN];

    struct pcap_api api;
    np_pcap *handle;

    FILE *file;
    int swapped;
    int nanos;
    uint8_t *buf;

    sniffer_thread thread;
    int thread_status;
};

int pcap_api_load(struct pcap_api *api, char *err, size_t errlen);
void pcap_api_unload(struct pcap_api *api);

int live_loop(struct sniffer *s, uint64_t max_frames);

int replay_open(struct sniffer *s, const char *path);
int replay_loop(struct sniffer *s, uint64_t max_frames);
void replay_close(struct sniffer *s);

void sniffer_deliver(struct sniffer *s, uint64_t ts_us, uint32_t caplen, uint32_t len,
                     const uint8_t *data);
int sniffer_fail(struct sniffer *s, int status, const char *fmt, ...);
void format_error(char *dst, size_t len, const char *fmt, ...);
void vformat_error(char *dst, size_t len, const char *fmt, va_list ap);
void copy_bounded(char *dst, size_t cap, const char *src);

int thread_spawn(sniffer_thread *t, void *(*fn)(void *), void *arg);
void thread_join(sniffer_thread t);
void sleep_us(uint64_t us);
uint64_t monotonic_us(void);

void flag_set(sniffer_flag *f, int value);
int flag_get(sniffer_flag *f);

#endif
