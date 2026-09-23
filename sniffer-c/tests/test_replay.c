#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "sniffer.h"

#define SAMPLE_FRAMES 200
#define SAMPLE_LINK_ETHERNET 1
#define ETH_HEADER_LEN 14
#define PCAP_HEADER_LEN 24
#define COPY_CHUNK 4096

static const char *g_sample = "tests/data/sample.pcap";
static const char *g_tmp_bad = "build/tmp_bad_magic.pcap";
static const char *g_tmp_cut = "build/tmp_truncated.pcap";

struct seen {
    uint64_t frames;
    uint64_t first_ts;
    uint64_t last_ts;
    int monotonic;
    int sizes_ok;
};

static void on_frame(const sniffer_frame *f, void *user)
{
    struct seen *s = user;
    if (s->frames == 0) {
        s->first_ts = f->ts_us;
    } else if (f->ts_us < s->last_ts) {
        s->monotonic = 0;
    }
    if (f->caplen != f->len || f->caplen < ETH_HEADER_LEN || !f->data) {
        s->sizes_ok = 0;
    }
    s->last_ts = f->ts_us;
    s->frames++;
}

static sniffer *open_sample(struct seen *seen)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    int status = sniffer_open_file(&s, g_sample, err, sizeof(err));
    CHECK(status == SNIFFER_OK);
    if (status != SNIFFER_OK) {
        fprintf(stderr, "  %s\n", err);
        return NULL;
    }
    memset(seen, 0, sizeof(*seen));
    seen->monotonic = 1;
    seen->sizes_ok = 1;
    CHECK(sniffer_set_callback(s, on_frame, seen) == SNIFFER_OK);
    return s;
}

static void test_full_replay(void)
{
    struct seen seen;
    sniffer_stats st;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_link_type(s) == SAMPLE_LINK_ETHERNET);
    CHECK(sniffer_run(s, 0) == SNIFFER_OK);
    CHECK(seen.frames == SAMPLE_FRAMES);
    CHECK(seen.monotonic);
    CHECK(seen.sizes_ok);
    CHECK(seen.last_ts > seen.first_ts);
    CHECK(sniffer_get_stats(s, &st) == SNIFFER_OK);
    CHECK(st.delivered == SAMPLE_FRAMES);
    CHECK(sniffer_run(s, 0) == SNIFFER_ERR_STATE);
    sniffer_close(s);
}

static void test_max_frames(void)
{
    struct seen seen;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_run(s, 10) == SNIFFER_OK);
    CHECK(seen.frames == 10);
    sniffer_close(s);
}

static void test_threaded_replay(void)
{
    struct seen seen;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_start(s) == SNIFFER_OK);
    CHECK(sniffer_start(s) == SNIFFER_ERR_STATE);
    CHECK(sniffer_stop(s) == SNIFFER_OK);
    CHECK(seen.frames <= SAMPLE_FRAMES);
    CHECK(sniffer_stop(s) == SNIFFER_ERR_STATE);
    sniffer_close(s);
}

static void test_finished_flag(void)
{
    struct seen seen;
    int status = -99;
    int rounds = 0;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_poll_finished(s, &status) == 0);
    CHECK(sniffer_start(s) == SNIFFER_OK);
    while (sniffer_poll_finished(s, &status) == 0 && rounds++ < 100000) {
    }
    CHECK(status == SNIFFER_OK);
    CHECK(seen.frames == SAMPLE_FRAMES);
    CHECK(sniffer_stop(s) == SNIFFER_OK);
    CHECK(sniffer_poll_finished(s, &status) == 0);
    CHECK(sniffer_poll_finished(s, NULL) == SNIFFER_ERR_ARG);
    sniffer_close(s);
}

static void test_realtime_stop_is_prompt(void)
{
    struct seen seen;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_set_realtime(s, 1) == SNIFFER_OK);
    CHECK(sniffer_start(s) == SNIFFER_OK);
    CHECK(sniffer_stop(s) == SNIFFER_OK);
    CHECK(seen.frames < SAMPLE_FRAMES);
    sniffer_close(s);
}

static void test_close_while_running(void)
{
    struct seen seen;
    sniffer *s = open_sample(&seen);
    if (!s) {
        return;
    }
    CHECK(sniffer_set_realtime(s, 1) == SNIFFER_OK);
    CHECK(sniffer_start(s) == SNIFFER_OK);
    sniffer_close(s);
}

static void test_missing_callback(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    CHECK(sniffer_open_file(&s, g_sample, err, sizeof(err)) == SNIFFER_OK);
    CHECK(sniffer_run(s, 0) == SNIFFER_ERR_STATE);
    CHECK(strstr(sniffer_last_error(s), "callback") != NULL);
    sniffer_close(s);
}

static void test_missing_file(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = (sniffer *)&err;
    CHECK(sniffer_open_file(&s, "build/does_not_exist.pcap", err, sizeof(err)) == SNIFFER_ERR_IO);
    CHECK(s == NULL);
    CHECK(err[0] != '\0');
}

static int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (!f) {
        return 0;
    }
    n = fwrite(data, 1, len, f);
    fclose(f);
    return n == len;
}

static void test_bad_magic(void)
{
    unsigned char junk[PCAP_HEADER_LEN] = {0x12, 0x34, 0x56, 0x78};
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    CHECK(write_file(g_tmp_bad, junk, sizeof(junk)));
    CHECK(sniffer_open_file(&s, g_tmp_bad, err, sizeof(err)) == SNIFFER_ERR_FORMAT);
    CHECK(strstr(err, "magic") != NULL);
    remove(g_tmp_bad);
}

static long file_prefix(const char *path, unsigned char *dst, long cap)
{
    FILE *f = fopen(path, "rb");
    long n;
    if (!f) {
        return -1;
    }
    n = (long)fread(dst, 1, (size_t)cap, f);
    fclose(f);
    return n;
}

static void test_truncated_record(void)
{
    unsigned char *buf = malloc(COPY_CHUNK);
    struct seen seen = {0, 0, 0, 1, 1};
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    long n;

    CHECK(buf != NULL);
    if (!buf) {
        return;
    }
    n = file_prefix(g_sample, buf, COPY_CHUNK);
    CHECK(n == COPY_CHUNK);
    CHECK(write_file(g_tmp_cut, buf, (size_t)n));
    free(buf);

    CHECK(sniffer_open_file(&s, g_tmp_cut, err, sizeof(err)) == SNIFFER_OK);
    if (s) {
        CHECK(sniffer_set_callback(s, on_frame, &seen) == SNIFFER_OK);
        CHECK(sniffer_run(s, 0) == SNIFFER_ERR_FORMAT);
        CHECK(seen.frames > 0 && seen.frames < SAMPLE_FRAMES);
        CHECK(strstr(sniffer_last_error(s), "truncated") != NULL);
        sniffer_close(s);
    }
    remove(g_tmp_cut);
}

static void test_argument_checks(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    CHECK(sniffer_open_file(NULL, g_sample, err, sizeof(err)) == SNIFFER_ERR_ARG);
    CHECK(sniffer_set_callback(NULL, on_frame, NULL) == SNIFFER_ERR_ARG);
    CHECK(sniffer_run(NULL, 0) == SNIFFER_ERR_ARG);
    CHECK(sniffer_stop(NULL) == SNIFFER_ERR_ARG);
    CHECK(strcmp(sniffer_status_str(SNIFFER_ERR_FORMAT), "bad pcap format") == 0);
    sniffer_close(NULL);
}

int main(void)
{
    RUN(test_full_replay);
    RUN(test_max_frames);
    RUN(test_threaded_replay);
    RUN(test_finished_flag);
    RUN(test_realtime_stop_is_prompt);
    RUN(test_close_while_running);
    RUN(test_missing_callback);
    RUN(test_missing_file);
    RUN(test_bad_magic);
    RUN(test_truncated_record);
    RUN(test_argument_checks);
    return check_summary();
}
