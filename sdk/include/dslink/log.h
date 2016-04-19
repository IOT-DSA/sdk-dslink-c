#ifndef SDK_DSLINK_C_LOG_H
#define SDK_DSLINK_C_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

#ifndef LOG_TAG
#define LOG_TAG ""
#error "LOG_TAG isn't properly defined. \
Define it as: `#define LOG_TAG "tag"` before the include."
#endif

// Global logging level
extern int dslink_log_lvl;

// Various predefined logging constants
#define LOG_LVL_OFF     0
#define LOG_LVL_FATAL 100
#define LOG_LVL_ERR   200
#define LOG_LVL_WARN  300
#define LOG_LVL_INFO  400
#define LOG_LVL_DEBUG 500

#define log_fatal(...) DSLINK_DO_LOG(LOG_LVL_FATAL, "FATAL", __VA_ARGS__)
#define log_err(...) DSLINK_DO_LOG(LOG_LVL_ERR, "ERROR", __VA_ARGS__)
#define log_warn(...) DSLINK_DO_LOG(LOG_LVL_WARN, "WARN", __VA_ARGS__)
#define log_info(...) DSLINK_DO_LOG(LOG_LVL_INFO, "INFO", __VA_ARGS__)
#define log_debug(...) DSLINK_DO_LOG(LOG_LVL_DEBUG, "DEBUG", __VA_ARGS__)

int dslink_log_set_lvl(const char *level);
void dslink_log_print_time();

#define LOG_LVL_CHK(arg) if (dslink_log_lvl >= arg)
#define DSLINK_LOG_GEN_LAYOUT(arg) arg " [" LOG_TAG "] - "
#define DSLINK_DO_LOG(lvl, pref, ...) \
    LOG_LVL_CHK(lvl) { \
        dslink_log_print_time(); \
        printf(" " DSLINK_LOG_GEN_LAYOUT(pref) __VA_ARGS__); \
    }

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LOG_H
