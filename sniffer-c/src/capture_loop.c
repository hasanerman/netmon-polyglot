#include "sniffer_internal.h"

#define PCAP_NEXT_OK 1
#define PCAP_NEXT_TIMEOUT 0
#define PCAP_NEXT_BREAK (-2)
#define MICROS_PER_SEC 1000000ull

int live_loop(struct sniffer *s, uint64_t max_frames)
{
    uint64_t seen = 0;

    while (!flag_get(&s->stop_requested)) {
        struct np_pkthdr *hdr = NULL;
        const uint8_t *data = NULL;
        int rc = s->api.next_ex(s->handle, &hdr, &data);

        if (rc == PCAP_NEXT_TIMEOUT) {
            continue;
        }
        if (rc == PCAP_NEXT_BREAK) {
            break;
        }
        if (rc != PCAP_NEXT_OK) {
            return sniffer_fail(s, SNIFFER_ERR_CAPTURE, "%s", s->api.geterr(s->handle));
        }

        sniffer_deliver(s,
                        (uint64_t)hdr->ts.tv_sec * MICROS_PER_SEC + (uint64_t)hdr->ts.tv_usec,
                        hdr->caplen, hdr->len, data);
        if (max_frames && ++seen >= max_frames) {
            break;
        }
    }
    return SNIFFER_OK;
}

#ifdef _WIN32

struct thread_start {
    void *(*fn)(void *);
    void *arg;
};

static DWORD WINAPI thread_trampoline(LPVOID param)
{
    struct thread_start start = *(struct thread_start *)param;
    HeapFree(GetProcessHeap(), 0, param);
    start.fn(start.arg);
    return 0;
}

int thread_spawn(sniffer_thread *t, void *(*fn)(void *), void *arg)
{
    struct thread_start *start = HeapAlloc(GetProcessHeap(), 0, sizeof(*start));
    if (!start) {
        return -1;
    }
    start->fn = fn;
    start->arg = arg;
    *t = CreateThread(NULL, 0, thread_trampoline, start, 0, NULL);
    if (!*t) {
        HeapFree(GetProcessHeap(), 0, start);
        return -1;
    }
    return 0;
}

void thread_join(sniffer_thread t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

void sleep_us(uint64_t us)
{
    Sleep((DWORD)(us / 1000u));
}

uint64_t monotonic_us(void)
{
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (uint64_t)(now.QuadPart / freq.QuadPart) * MICROS_PER_SEC +
           (uint64_t)(now.QuadPart % freq.QuadPart) * MICROS_PER_SEC / (uint64_t)freq.QuadPart;
}

void flag_set(sniffer_flag *f, int value)
{
    InterlockedExchange(f, value);
}

int flag_get(sniffer_flag *f)
{
    return (int)InterlockedCompareExchange(f, 0, 0);
}

#else

#include <time.h>

int thread_spawn(sniffer_thread *t, void *(*fn)(void *), void *arg)
{
    return pthread_create(t, NULL, fn, arg);
}

void thread_join(sniffer_thread t)
{
    pthread_join(t, NULL);
}

void sleep_us(uint64_t us)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(us / MICROS_PER_SEC);
    ts.tv_nsec = (long)((us % MICROS_PER_SEC) * 1000u);
    nanosleep(&ts, NULL);
}

uint64_t monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * MICROS_PER_SEC + (uint64_t)ts.tv_nsec / 1000u;
}

void flag_set(sniffer_flag *f, int value)
{
    __atomic_store_n(f, value, __ATOMIC_SEQ_CST);
}

int flag_get(sniffer_flag *f)
{
    return __atomic_load_n(f, __ATOMIC_SEQ_CST);
}

#endif
