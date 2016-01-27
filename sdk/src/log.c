#define LOG_TAG "log"

#include <time.h>
#include "dslink/log.h"
#include "dslink/utils.h"

int dslink_log_lvl = LOG_LVL_INFO;

int dslink_log_set_lvl(const char *level) {
    if (dslink_strcasecmp(level, "off") == 0
        || dslink_strcasecmp(level, "none") == 0) {
        dslink_log_lvl = LOG_LVL_OFF;
    } else if (dslink_strcasecmp(level, "fatal") == 0) {
        dslink_log_lvl = LOG_LVL_FATAL;
    } else if (dslink_strcasecmp(level, "error") == 0) {
        dslink_log_lvl = LOG_LVL_ERR;
    } else if (dslink_strcasecmp(level, "warn") == 0) {
        dslink_log_lvl = LOG_LVL_WARN;
    } else if (dslink_strcasecmp(level, "info") == 0) {
        dslink_log_lvl = LOG_LVL_INFO;
#ifndef NDEBUG
    } else if (dslink_strcasecmp(level, "debug") == 0) {
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
