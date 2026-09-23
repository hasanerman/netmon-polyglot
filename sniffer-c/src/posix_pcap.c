#ifndef _WIN32

#include <dlfcn.h>
#include <string.h>

#include "sniffer_internal.h"

static const char *const LIB_NAMES[] = {"libpcap.so.1", "libpcap.so", "libpcap.dylib"};

#define LOAD_SYM(api, field, name)                  \
    do {                                            \
        void *p_ = dlsym((api)->lib, name);         \
        if (!p_) {                                  \
            missing = name;                         \
            goto fail;                              \
        }                                           \
        memcpy(&(api)->field, &p_, sizeof(p_));     \
    } while (0)

int pcap_api_load(struct pcap_api *api, char *err, size_t errlen)
{
    const char *missing = NULL;
    size_t i;

    memset(api, 0, sizeof(*api));
    for (i = 0; i < sizeof(LIB_NAMES) / sizeof(LIB_NAMES[0]) && !api->lib; i++) {
        api->lib = dlopen(LIB_NAMES[i], RTLD_NOW | RTLD_LOCAL);
    }
    if (!api->lib) {
        format_error(err, errlen, "libpcap not found, install libpcap (apt install libpcap0.8)");
        return SNIFFER_ERR_NO_LIBRARY;
    }

    LOAD_SYM(api, open_live, "pcap_open_live");
    LOAD_SYM(api, next_ex, "pcap_next_ex");
    LOAD_SYM(api, close, "pcap_close");
    LOAD_SYM(api, datalink, "pcap_datalink");
    LOAD_SYM(api, geterr, "pcap_geterr");
    LOAD_SYM(api, stats, "pcap_stats");
    LOAD_SYM(api, breakloop, "pcap_breakloop");
    LOAD_SYM(api, findalldevs, "pcap_findalldevs");
    LOAD_SYM(api, freealldevs, "pcap_freealldevs");
    return SNIFFER_OK;

fail:
    format_error(err, errlen, "libpcap lacks symbol %s", missing);
    pcap_api_unload(api);
    return SNIFFER_ERR_NO_LIBRARY;
}

void pcap_api_unload(struct pcap_api *api)
{
    if (api->lib) {
        dlclose(api->lib);
    }
    memset(api, 0, sizeof(*api));
}

#endif
