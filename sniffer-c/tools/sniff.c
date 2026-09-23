#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sniffer.h"

#define MAX_DEVICES 64
#define DEFAULT_SNAPLEN 65535
#define DEFAULT_LIVE_FRAMES 20
#define EXIT_USAGE 2

struct tally {
    uint64_t frames;
    uint64_t bytes;
    int verbose;
};

static void on_frame(const sniffer_frame *f, void *user)
{
    struct tally *t = user;
    t->frames++;
    t->bytes += f->len;
    if (t->verbose) {
        printf("%llu.%06llu  caplen %-5u len %u\n",
               (unsigned long long)(f->ts_us / 1000000u),
               (unsigned long long)(f->ts_us % 1000000u), f->caplen, f->len);
    }
}

static int usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "  sniff list\n"
            "  sniff live <device> [frames] [--promisc]\n"
            "  sniff replay <file.pcap>\n");
    return EXIT_USAGE;
}

static int report_error(int status, const char *detail)
{
    fprintf(stderr, "error: %s (%s)\n", sniffer_status_str(status), detail);
    return 1;
}

static int cmd_list(void)
{
    sniffer_device devs[MAX_DEVICES];
    char err[SNIFFER_ERRBUF_LEN] = {0};
    size_t total = 0;
    size_t i;
    int status = sniffer_list_devices(devs, MAX_DEVICES, &total, err, sizeof(err));

    if (status != SNIFFER_OK) {
        return report_error(status, err);
    }
    for (i = 0; i < total && i < MAX_DEVICES; i++) {
        printf("%-60s %s%s\n", devs[i].name, devs[i].description,
               (devs[i].flags & SNIFFER_DEV_LOOPBACK) ? " [loopback]" : "");
    }
    printf("%zu device(s)\n", total);
    return 0;
}

static int run_and_report(sniffer *s, uint64_t max_frames, int verbose)
{
    struct tally t = {0, 0, verbose};
    sniffer_stats st;
    int status = sniffer_set_callback(s, on_frame, &t);

    if (status == SNIFFER_OK) {
        status = sniffer_run(s, max_frames);
    }
    if (status != SNIFFER_OK) {
        report_error(status, sniffer_last_error(s));
        sniffer_close(s);
        return 1;
    }
    if (sniffer_get_stats(s, &st) == SNIFFER_OK) {
        printf("link type %d, frames %llu, bytes %llu, dropped %u\n", sniffer_link_type(s),
               (unsigned long long)t.frames, (unsigned long long)t.bytes, st.dropped);
    }
    sniffer_close(s);
    return 0;
}

static int cmd_live(int argc, char **argv)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    uint64_t frames = DEFAULT_LIVE_FRAMES;
    int promisc = 0;
    sniffer *s = NULL;
    int i, status;

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--promisc") == 0) {
            promisc = 1;
        } else {
            frames = strtoull(argv[i], NULL, 10);
        }
    }
    status = sniffer_open_live(&s, argv[2], DEFAULT_SNAPLEN, promisc, err, sizeof(err));
    if (status != SNIFFER_OK) {
        return report_error(status, err);
    }
    return run_and_report(s, frames, 1);
}

static int cmd_replay(const char *path)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    int status = sniffer_open_file(&s, path, err, sizeof(err));

    if (status != SNIFFER_OK) {
        return report_error(status, err);
    }
    return run_and_report(s, 0, 0);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "list") == 0) {
        return cmd_list();
    }
    if (argc >= 3 && strcmp(argv[1], "live") == 0) {
        return cmd_live(argc, argv);
    }
    if (argc == 3 && strcmp(argv[1], "replay") == 0) {
        return cmd_replay(argv[2]);
    }
    return usage();
}
