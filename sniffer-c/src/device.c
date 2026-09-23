#include <string.h>

#include "sniffer_internal.h"

static void copy_device(sniffer_device *dst, const struct np_if *src)
{
    copy_bounded(dst->name, sizeof(dst->name), src->name);
    copy_bounded(dst->description, sizeof(dst->description), src->description);
    dst->flags = src->flags & (SNIFFER_DEV_LOOPBACK | SNIFFER_DEV_UP | SNIFFER_DEV_RUNNING);
}

int sniffer_list_devices(sniffer_device *out, size_t capacity, size_t *total,
                         char *errbuf, size_t errlen)
{
    char pcap_err[NP_ERRBUF_SIZE] = {0};
    struct pcap_api api;
    struct np_if *devs = NULL;
    const struct np_if *d;
    size_t count = 0;
    int status;

    if (!total || (capacity > 0 && !out)) {
        format_error(errbuf, errlen, "invalid argument");
        return SNIFFER_ERR_ARG;
    }
    *total = 0;

    status = pcap_api_load(&api, errbuf, errlen);
    if (status != SNIFFER_OK) {
        return status;
    }
    if (api.findalldevs(&devs, pcap_err) != 0) {
        format_error(errbuf, errlen, "device enumeration failed: %s", pcap_err);
        status = SNIFFER_ERR_OPEN;
        goto cleanup;
    }

    for (d = devs; d; d = d->next) {
        if (count < capacity) {
            copy_device(&out[count], d);
        }
        count++;
    }
    *total = count;

cleanup:
    if (devs) {
        api.freealldevs(devs);
    }
    pcap_api_unload(&api);
    return status;
}
