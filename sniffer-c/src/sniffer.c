#include <stdlib.h>
#include <string.h>

#include "sniffer_internal.h"

#define MIN_SNAPLEN 64
#define MAX_SNAPLEN 262144

static int classify_open_error(const char *msg)
{
    if (strstr(msg, "ermission") || strstr(msg, "not permitted") || strstr(msg, "ccess is denied")) {
        return SNIFFER_ERR_PERMISSION;
    }
    return SNIFFER_ERR_OPEN;
}

static struct sniffer *sniffer_alloc(enum source_kind kind)
{
    struct sniffer *s = calloc(1, sizeof(*s));
    if (s) {
        s->kind = kind;
        s->state = STATE_IDLE;
    }
    return s;
}

int sniffer_open_live(sniffer **out, const char *iface, int snaplen, int promisc,
                      char *errbuf, size_t errlen)
{
    char pcap_err[NP_ERRBUF_SIZE] = {0};
    struct sniffer *s;
    int status;

    if (!out || !iface || snaplen < MIN_SNAPLEN || snaplen > MAX_SNAPLEN) {
        format_error(errbuf, errlen, "invalid argument");
        return SNIFFER_ERR_ARG;
    }
    *out = NULL;

    s = sniffer_alloc(SOURCE_LIVE);
    if (!s) {
        format_error(errbuf, errlen, "out of memory");
        return SNIFFER_ERR_NOMEM;
    }

    status = pcap_api_load(&s->api, errbuf, errlen);
    if (status != SNIFFER_OK) {
        goto fail;
    }

    s->handle = s->api.open_live(iface, snaplen, promisc ? 1 : 0, NP_READ_TIMEOUT_MS, pcap_err);
    if (!s->handle) {
        status = classify_open_error(pcap_err);
        format_error(errbuf, errlen, "cannot open %s: %s", iface, pcap_err);
        goto fail;
    }
    s->link_type = s->api.datalink(s->handle);
    *out = s;
    return SNIFFER_OK;

fail:
    pcap_api_unload(&s->api);
    free(s);
    return status;
}

int sniffer_open_file(sniffer **out, const char *path, char *errbuf, size_t errlen)
{
    struct sniffer *s;
    int status;

    if (!out || !path) {
        format_error(errbuf, errlen, "invalid argument");
        return SNIFFER_ERR_ARG;
    }
    *out = NULL;

    s = sniffer_alloc(SOURCE_FILE);
    if (!s) {
        format_error(errbuf, errlen, "out of memory");
        return SNIFFER_ERR_NOMEM;
    }

    status = replay_open(s, path);
    if (status != SNIFFER_OK) {
        copy_bounded(errbuf, errlen, s->err);
        replay_close(s);
        free(s);
        return status;
    }
    *out = s;
    return SNIFFER_OK;
}

int sniffer_set_callback(sniffer *s, sniffer_callback cb, void *user)
{
    if (!s || !cb) {
        return SNIFFER_ERR_ARG;
    }
    if (s->state == STATE_RUNNING) {
        return sniffer_fail(s, SNIFFER_ERR_STATE, "cannot change callback while running");
    }
    s->callback = cb;
    s->user = user;
    return SNIFFER_OK;
}

int sniffer_set_realtime(sniffer *s, int enabled)
{
    if (!s) {
        return SNIFFER_ERR_ARG;
    }
    if (s->kind != SOURCE_FILE) {
        return sniffer_fail(s, SNIFFER_ERR_STATE, "realtime pacing only applies to file replay");
    }
    s->realtime = enabled ? 1 : 0;
    return SNIFFER_OK;
}

static int check_can_run(struct sniffer *s)
{
    if (!s->callback) {
        return sniffer_fail(s, SNIFFER_ERR_STATE, "no callback set");
    }
    if (s->state != STATE_IDLE) {
        return sniffer_fail(s, SNIFFER_ERR_STATE, "capture already started");
    }
    return SNIFFER_OK;
}

static int run_source(struct sniffer *s, uint64_t max_frames)
{
    return s->kind == SOURCE_LIVE ? live_loop(s, max_frames) : replay_loop(s, max_frames);
}

int sniffer_run(sniffer *s, uint64_t max_frames)
{
    int status;

    if (!s) {
        return SNIFFER_ERR_ARG;
    }
    status = check_can_run(s);
    if (status != SNIFFER_OK) {
        return status;
    }
    s->state = STATE_RUNNING;
    status = run_source(s, max_frames);
    s->state = STATE_FINISHED;
    return status;
}

static void *capture_thread(void *arg)
{
    struct sniffer *s = arg;
    s->thread_status = run_source(s, 0);
    flag_set(&s->finished, 1);
    return NULL;
}

int sniffer_poll_finished(sniffer *s, int *status)
{
    if (!s || !status) {
        return SNIFFER_ERR_ARG;
    }
    if (s->state != STATE_RUNNING || !flag_get(&s->finished)) {
        return 0;
    }
    *status = s->thread_status;
    return 1;
}

int sniffer_start(sniffer *s)
{
    int status;

    if (!s) {
        return SNIFFER_ERR_ARG;
    }
    status = check_can_run(s);
    if (status != SNIFFER_OK) {
        return status;
    }
    flag_set(&s->stop_requested, 0);
    flag_set(&s->finished, 0);
    s->state = STATE_RUNNING;
    if (thread_spawn(&s->thread, capture_thread, s) != 0) {
        s->state = STATE_IDLE;
        return sniffer_fail(s, SNIFFER_ERR_THREAD, "cannot create capture thread");
    }
    return SNIFFER_OK;
}

int sniffer_stop(sniffer *s)
{
    if (!s) {
        return SNIFFER_ERR_ARG;
    }
    if (s->state != STATE_RUNNING) {
        return sniffer_fail(s, SNIFFER_ERR_STATE, "capture is not running");
    }
    flag_set(&s->stop_requested, 1);
    if (s->kind == SOURCE_LIVE) {
        s->api.breakloop(s->handle);
    }
    thread_join(s->thread);
    s->state = STATE_FINISHED;
    return s->thread_status;
}

int sniffer_link_type(const sniffer *s)
{
    return s ? s->link_type : SNIFFER_ERR_ARG;
}

int sniffer_get_stats(sniffer *s, sniffer_stats *out)
{
    struct np_stat ps;

    if (!s || !out) {
        return SNIFFER_ERR_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->delivered = s->delivered;
    if (s->kind != SOURCE_LIVE) {
        out->received = (uint32_t)s->delivered;
        return SNIFFER_OK;
    }
    memset(&ps, 0, sizeof(ps));
    if (s->api.stats(s->handle, &ps) != 0) {
        return sniffer_fail(s, SNIFFER_ERR_CAPTURE, "%s", s->api.geterr(s->handle));
    }
    out->received = ps.ps_recv;
    out->dropped = ps.ps_drop;
    out->if_dropped = ps.ps_ifdrop;
    return SNIFFER_OK;
}

const char *sniffer_last_error(const sniffer *s)
{
    return s ? s->err : "null sniffer";
}

const char *sniffer_status_str(int status)
{
    switch (status) {
    case SNIFFER_OK: return "ok";
    case SNIFFER_ERR_ARG: return "invalid argument";
    case SNIFFER_ERR_NO_LIBRARY: return "capture library (npcap/libpcap) not installed";
    case SNIFFER_ERR_OPEN: return "cannot open capture source";
    case SNIFFER_ERR_PERMISSION: return "permission denied (run as administrator/root)";
    case SNIFFER_ERR_STATE: return "invalid state";
    case SNIFFER_ERR_THREAD: return "thread error";
    case SNIFFER_ERR_IO: return "i/o error";
    case SNIFFER_ERR_FORMAT: return "bad pcap format";
    case SNIFFER_ERR_NOMEM: return "out of memory";
    case SNIFFER_ERR_CAPTURE: return "capture error";
    default: return "unknown status";
    }
}

void sniffer_close(sniffer *s)
{
    if (!s) {
        return;
    }
    if (s->state == STATE_RUNNING) {
        sniffer_stop(s);
    }
    if (s->handle) {
        s->api.close(s->handle);
    }
    pcap_api_unload(&s->api);
    replay_close(s);
    free(s);
}

void sniffer_deliver(struct sniffer *s, uint64_t ts_us, uint32_t caplen, uint32_t len,
                     const uint8_t *data)
{
    sniffer_frame frame;
    frame.ts_us = ts_us;
    frame.caplen = caplen;
    frame.len = len;
    frame.data = data;
    s->callback(&frame, s->user);
    s->delivered++;
}

int sniffer_fail(struct sniffer *s, int status, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vformat_error(s->err, sizeof(s->err), fmt, ap);
    va_end(ap);
    return status;
}

void vformat_error(char *dst, size_t len, const char *fmt, va_list ap)
{
    if (!dst || len == 0) {
        return;
    }
    vsnprintf(dst, len, fmt, ap);
    dst[len - 1] = '\0';
}

void format_error(char *dst, size_t len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vformat_error(dst, len, fmt, ap);
    va_end(ap);
}

void copy_bounded(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (!dst || cap == 0) {
        return;
    }
    n = src ? strlen(src) : 0;
    if (n >= cap) {
        n = cap - 1;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}
