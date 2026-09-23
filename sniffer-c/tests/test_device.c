#include <string.h>

#include "check.h"
#include "sniffer.h"

#define DEVICE_CAP 32
#define BAD_IFACE "no-such-interface-xyz"
#define SNAPLEN 65535

static int g_library_present = 0;

static void test_list_devices(void)
{
    sniffer_device devs[DEVICE_CAP];
    char err[SNIFFER_ERRBUF_LEN] = {0};
    size_t total = 0;
    size_t i;
    int status = sniffer_list_devices(devs, DEVICE_CAP, &total, err, sizeof(err));

    if (status == SNIFFER_ERR_NO_LIBRARY || status == SNIFFER_ERR_OPEN) {
        printf("  capture not available here, skipping: %s\n", err);
        return;
    }
    g_library_present = 1;
    CHECK(status == SNIFFER_OK);
    for (i = 0; i < total && i < DEVICE_CAP; i++) {
        CHECK(devs[i].name[0] != '\0');
        CHECK(memchr(devs[i].name, '\0', sizeof(devs[i].name)) != NULL);
    }
    printf("  %zu device(s)\n", total);
}

static void test_count_only(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    size_t total = 0;
    int status;
    if (!g_library_present) {
        return;
    }
    status = sniffer_list_devices(NULL, 0, &total, err, sizeof(err));
    CHECK(status == SNIFFER_OK);
}

static void test_bad_interface(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer *s = NULL;
    int status;
    if (!g_library_present) {
        return;
    }
    status = sniffer_open_live(&s, BAD_IFACE, SNAPLEN, 0, err, sizeof(err));
    CHECK(status == SNIFFER_ERR_OPEN || status == SNIFFER_ERR_PERMISSION);
    CHECK(s == NULL);
    CHECK(err[0] != '\0');
}

static void test_argument_checks(void)
{
    char err[SNIFFER_ERRBUF_LEN] = {0};
    sniffer_device dev;
    sniffer *s = NULL;
    CHECK(sniffer_list_devices(&dev, 1, NULL, err, sizeof(err)) == SNIFFER_ERR_ARG);
    CHECK(sniffer_list_devices(NULL, 4, &(size_t){0}, err, sizeof(err)) == SNIFFER_ERR_ARG);
    CHECK(sniffer_open_live(&s, NULL, SNAPLEN, 0, err, sizeof(err)) == SNIFFER_ERR_ARG);
    CHECK(sniffer_open_live(&s, "x", 10, 0, err, sizeof(err)) == SNIFFER_ERR_ARG);
}

int main(void)
{
    RUN(test_list_devices);
    RUN(test_count_only);
    RUN(test_bad_interface);
    RUN(test_argument_checks);
    return check_summary();
}
