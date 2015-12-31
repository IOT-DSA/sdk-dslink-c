#include <stdlib.h>
#include "dslink/timer.h"

static inline
uint32_t dslink_timer_diff(struct timeval *start,
                           struct timeval *stop) {
    uint64_t startMs = (uint64_t) (start->tv_sec * 1000)
                       + (start->tv_usec / 1000);
    uint64_t endMs = (uint64_t) (stop->tv_sec * 1000)
                     + (stop->tv_usec / 1000);
    return (uint32_t) (endMs - startMs);
}

void dslink_timer_start(Timer *timer) {
    gettimeofday(&timer->start, NULL);
}

uint32_t dslink_timer_stop(Timer *timer) {
    gettimeofday(&timer->stop, NULL);
    return dslink_timer_diff(&timer->start, &timer->stop);
}
