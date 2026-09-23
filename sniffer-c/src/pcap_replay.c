#include <stdlib.h>
#include <string.h>

#include "sniffer_internal.h"

#define GLOBAL_HEADER_LEN 24
#define RECORD_HEADER_LEN 16
#define MAGIC_MICROS 0xA1B2C3D4u
#define MAGIC_NANOS 0xA1B23C4Du
#define NANOS_PER_MICRO 1000u
#define MICROS_PER_SEC 1000000ull
#define MAX_PACING_GAP_US 1000000ull
#define PACING_SLICE_US 50000ull
#define MIN_SLEEP_US 2000ull

static uint32_t swap32(uint32_t v)
{
    return (v >> 24) | ((v >> 8) & 0x0000FF00u) | ((v << 8) & 0x00FF0000u) | (v << 24);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t field32(const struct sniffer *s, const uint8_t *p)
{
    uint32_t v = read_le32(p);
    return s->swapped ? swap32(v) : v;
}

static int parse_magic(struct sniffer *s, uint32_t magic)
{
    if (magic == MAGIC_MICROS || magic == MAGIC_NANOS) {
        s->swapped = 0;
    } else if (swap32(magic) == MAGIC_MICROS || swap32(magic) == MAGIC_NANOS) {
        s->swapped = 1;
        magic = swap32(magic);
    } else {
        return sniffer_fail(s, SNIFFER_ERR_FORMAT, "not a pcap file (magic 0x%08x)", magic);
    }
    s->nanos = magic == MAGIC_NANOS;
    return SNIFFER_OK;
}

int replay_open(struct sniffer *s, const char *path)
{
    uint8_t header[GLOBAL_HEADER_LEN];
    int status;

    s->file = fopen(path, "rb");
    if (!s->file) {
        return sniffer_fail(s, SNIFFER_ERR_IO, "cannot open %s", path);
    }
    if (fread(header, 1, sizeof(header), s->file) != sizeof(header)) {
        return sniffer_fail(s, SNIFFER_ERR_FORMAT, "file shorter than pcap header");
    }
    status = parse_magic(s, read_le32(header));
    if (status != SNIFFER_OK) {
        return status;
    }
    s->link_type = (int)field32(s, header + 20);

    s->buf = malloc(REPLAY_MAX_RECORD);
    if (!s->buf) {
        return sniffer_fail(s, SNIFFER_ERR_NOMEM, "out of memory");
    }
    return SNIFFER_OK;
}

struct pacer {
    uint64_t first_ts;
    uint64_t wall_start;
};

static void pace(struct sniffer *s, struct pacer *p, uint64_t ts)
{
    uint64_t now = monotonic_us();
    uint64_t target;

    if (!s->realtime) {
        return;
    }
    // uzun bosluklarda bekleme, saati yeniden hizala
    if (p->wall_start == 0 || ts < p->first_ts || ts - p->first_ts > now - p->wall_start + MAX_PACING_GAP_US) {
        p->first_ts = ts;
        p->wall_start = now;
        return;
    }
    target = p->wall_start + (ts - p->first_ts);
    while (!flag_get(&s->stop_requested) && target > now + MIN_SLEEP_US) {
        uint64_t ahead = target - now;
        sleep_us(ahead < PACING_SLICE_US ? ahead : PACING_SLICE_US);
        now = monotonic_us();
    }
}

int replay_loop(struct sniffer *s, uint64_t max_frames)
{
    uint8_t rec[RECORD_HEADER_LEN];
    struct pacer pacer = {0, 0};
    uint64_t seen = 0;

    while (!flag_get(&s->stop_requested)) {
        size_t got = fread(rec, 1, sizeof(rec), s->file);
        uint32_t caplen, len, frac;
        uint64_t ts;

        if (got == 0 && feof(s->file)) {
            break;
        }
        if (got != sizeof(rec)) {
            return sniffer_fail(s, SNIFFER_ERR_FORMAT, "truncated record header");
        }
        caplen = field32(s, rec + 8);
        len = field32(s, rec + 12);
        if (caplen > REPLAY_MAX_RECORD) {
            return sniffer_fail(s, SNIFFER_ERR_FORMAT, "record of %u bytes exceeds limit", caplen);
        }
        if (fread(s->buf, 1, caplen, s->file) != caplen) {
            return sniffer_fail(s, SNIFFER_ERR_FORMAT, "truncated record data");
        }

        frac = field32(s, rec + 4);
        ts = (uint64_t)field32(s, rec) * MICROS_PER_SEC + (s->nanos ? frac / NANOS_PER_MICRO : frac);
        pace(s, &pacer, ts);

        sniffer_deliver(s, ts, caplen, len, s->buf);
        if (max_frames && ++seen >= max_frames) {
            break;
        }
    }
    if (ferror(s->file)) {
        return sniffer_fail(s, SNIFFER_ERR_IO, "read error");
    }
    return SNIFFER_OK;
}

void replay_close(struct sniffer *s)
{
    if (s->file) {
        fclose(s->file);
        s->file = NULL;
    }
    free(s->buf);
    s->buf = NULL;
}
