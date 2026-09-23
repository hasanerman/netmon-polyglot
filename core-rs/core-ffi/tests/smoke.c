#include <stdio.h>
#include <string.h>

#include "core_ffi.h"

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <time.h>
static void sleep_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}
#endif

#define EXPECTED_FRAMES 200u
#define WAIT_ROUNDS 2000
#define WAIT_STEP_MS 5
#define TOP_FLOWS 3

_Static_assert(sizeof(NcConfig) == 20, "NcConfig layout");
_Static_assert(sizeof(NcStats) == 200, "NcStats layout");
_Static_assert(sizeof(NcFlow) == 88, "NcFlow layout");
_Static_assert(sizeof(NcAlert) == 304, "NcAlert layout");
_Static_assert(sizeof(NcDevice) == 516, "NcDevice layout");

static int fail(NcCore *core, const char *what, int rc)
{
    char err[256] = {0};
    core_last_error(core, err, sizeof(err));
    fprintf(stderr, "%s failed: %s (%s)\n", what, core_status_str(rc), err);
    core_destroy(core);
    return 1;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "sample.pcap";
    NcFlow flows[TOP_FLOWS];
    NcStats stats;
    uint32_t written = 0;
    NcCore *core;
    int rc, i;

    if (core_abi_version() != NC_ABI_VERSION) {
        fprintf(stderr, "abi mismatch\n");
        return 1;
    }
    core = core_create(NULL);
    if (!core) {
        fprintf(stderr, "core_create failed\n");
        return 1;
    }
    if ((rc = core_open_file(core, path, 0)) != NC_STATUS_OK) {
        return fail(core, "core_open_file", rc);
    }
    if ((rc = core_start(core)) != NC_STATUS_OK) {
        return fail(core, "core_start", rc);
    }
    for (i = 0; i < WAIT_ROUNDS; i++) {
        core_poll_stats(core, &stats);
        if (stats.packets >= EXPECTED_FRAMES) {
            break;
        }
        sleep_ms(WAIT_STEP_MS);
    }
    core_stop(core);

    core_poll_stats(core, &stats);
    core_poll_top_flows(core, flows, TOP_FLOWS, &written);
    printf("packets %llu tcp %llu udp %llu flows %llu top %u\n",
           (unsigned long long)stats.packets, (unsigned long long)stats.tcp,
           (unsigned long long)stats.udp, (unsigned long long)stats.active_flows, written);
    core_destroy(core);
    return stats.packets == EXPECTED_FRAMES && written == TOP_FLOWS ? 0 : 1;
}
