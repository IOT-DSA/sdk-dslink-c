#ifndef SDK_DSLINK_C_TIMER_H
#define SDK_DSLINK_C_TIMER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include <stdint.h>

typedef struct Timer {
    struct timeval start;
    struct timeval stop;
} Timer;

void dslink_timer_start(Timer *timer);
uint32_t dslink_timer_stop(Timer *timer);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_TIMER_H
