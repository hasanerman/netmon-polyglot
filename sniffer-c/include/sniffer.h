#ifndef SNIFFER_H
#define SNIFFER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SNIFFER_API_VERSION 1
#define SNIFFER_ERRBUF_LEN 256
#define SNIFFER_NAME_LEN 256

#define SNIFFER_DEV_LOOPBACK 0x1u
#define SNIFFER_DEV_UP 0x2u
#define SNIFFER_DEV_RUNNING 0x4u

typedef enum sniffer_status {
    SNIFFER_OK = 0,
    SNIFFER_ERR_ARG = -1,
    SNIFFER_ERR_NO_LIBRARY = -2,
    SNIFFER_ERR_OPEN = -3,
    SNIFFER_ERR_PERMISSION = -4,
    SNIFFER_ERR_STATE = -5,
    SNIFFER_ERR_THREAD = -6,
    SNIFFER_ERR_IO = -7,
    SNIFFER_ERR_FORMAT = -8,
    SNIFFER_ERR_NOMEM = -9,
    SNIFFER_ERR_CAPTURE = -10
} sniffer_status;

typedef struct sniffer_frame {
    uint64_t ts_us;
    uint32_t caplen;
    uint32_t len;
    const uint8_t *data;
} sniffer_frame;

typedef struct sniffer_device {
    char name[SNIFFER_NAME_LEN];
    char description[SNIFFER_NAME_LEN];
    uint32_t flags;
} sniffer_device;

typedef struct sniffer_stats {
    uint64_t delivered;
    uint32_t received;
    uint32_t dropped;
    uint32_t if_dropped;
} sniffer_stats;

/* data is only valid during the call; copy it if you need it later */
typedef void (*sniffer_callback)(const sniffer_frame *frame, void *user);

typedef struct sniffer sniffer;

int sniffer_list_devices(sniffer_device *out, size_t capacity, size_t *total,
                         char *errbuf, size_t errlen);

int sniffer_open_live(sniffer **out, const char *iface, int snaplen, int promisc,
                      char *errbuf, size_t errlen);
int sniffer_open_file(sniffer **out, const char *path, char *errbuf, size_t errlen);

int sniffer_set_callback(sniffer *s, sniffer_callback cb, void *user);
int sniffer_set_realtime(sniffer *s, int enabled);

int sniffer_run(sniffer *s, uint64_t max_frames);
int sniffer_start(sniffer *s);
int sniffer_stop(sniffer *s);
/* 1 when a started capture has ended on its own (eof or error); status gets its result */
int sniffer_poll_finished(sniffer *s, int *status);

int sniffer_link_type(const sniffer *s);
int sniffer_get_stats(sniffer *s, sniffer_stats *out);
const char *sniffer_last_error(const sniffer *s);
const char *sniffer_status_str(int status);

void sniffer_close(sniffer *s);

#ifdef __cplusplus
}
#endif

#endif
