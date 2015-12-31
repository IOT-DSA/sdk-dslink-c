#define LOG_TAG "log"

#include <time.h>
#include <string.h>
#include "dslink/log.h"
#include "dslink/utils.h"

int dslink_log_lvl = LOG_LVL_INFO;

int dslink_log_set_lvl(char *level, size_t len) {
    dslink_strlwr(level, len);
    if (strncmp(level, "off", len) == 0
        || strncmp(level, "none", len) == 0) {
        dslink_log_lvl = LOG_LVL_OFF;
    } else if (strncmp(level, "fatal", len) == 0) {
        dslink_log_lvl = LOG_LVL_FATAL;
    } else if (strncmp(level, "error", len) == 0) {
        dslink_log_lvl = LOG_LVL_ERR;
    } else if (strncmp(level, "warn", len) == 0) {
        dslink_log_lvl = LOG_LVL_WARN;
    } else if (strncmp(level, "info", len) == 0) {
        dslink_log_lvl = LOG_LVL_INFO;
#ifndef NDEBUG
    } else if (strncmp(level, "debug", len) == 0) {
        dslink_log_lvl = LOG_LVL_DEBUG;
#endif
    } else {
        return 1;
    }
    return 0;
}

void dslink_log_print_time() {
    char buf[20];
    time_t now = time(NULL);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("%s", buf);
}
