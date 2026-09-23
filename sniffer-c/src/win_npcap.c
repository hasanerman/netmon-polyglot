#ifdef _WIN32

#include <string.h>

#include "sniffer_internal.h"

#define NPCAP_SUBDIR "\\Npcap\\wpcap.dll"
#define LEGACY_DLL "wpcap.dll"

static HMODULE load_wpcap(void)
{
    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, MAX_PATH);
    HMODULE lib = NULL;

    if (n > 0 && n + sizeof(NPCAP_SUBDIR) < MAX_PATH) {
        memcpy(path + n, NPCAP_SUBDIR, sizeof(NPCAP_SUBDIR));
        // altered search path: packet.dll ayni klasorden gelsin
        lib = LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (!lib) {
        lib = LoadLibraryA(LEGACY_DLL);
    }
    return lib;
}

#define LOAD_SYM(api, field, name)                                   \
    do {                                                             \
        FARPROC p_ = GetProcAddress((HMODULE)(api)->lib, name);      \
        if (!p_) {                                                   \
            missing = name;                                          \
            goto fail;                                               \
        }                                                            \
        memcpy(&(api)->field, &p_, sizeof(p_));                      \
    } while (0)

int pcap_api_load(struct pcap_api *api, char *err, size_t errlen)
{
    const char *missing = NULL;

    memset(api, 0, sizeof(*api));
    api->lib = load_wpcap();
    if (!api->lib) {
        format_error(err, errlen, "wpcap.dll not found, install npcap from https://npcap.com");
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
    format_error(err, errlen, "wpcap.dll lacks symbol %s", missing);
    pcap_api_unload(api);
    return SNIFFER_ERR_NO_LIBRARY;
}

void pcap_api_unload(struct pcap_api *api)
{
    if (api->lib) {
        FreeLibrary((HMODULE)api->lib);
    }
    memset(api, 0, sizeof(*api));
}

#endif
