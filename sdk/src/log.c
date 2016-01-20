#define LOG_TAG "log"

#include <time.h>
#include <string.h>
#include "dslink/log.h"
#include "dslink/utils.h"

int dslink_log_lvl = LOG_LVL_INFO;

int dslink_log_set_lvl(const char *level) {
    if (dslink_strcasestr(level, "off") != NULL
        || dslink_strcasestr(level, "none") != NULL) {
        dslink_log_lvl = LOG_LVL_OFF;
    } else if (dslink_strcasestr(level, "fatal") != NULL) {
        dslink_log_lvl = LOG_LVL_FATAL;
    } else if (dslink_strcasestr(level, "error") != NULL) {
        dslink_log_lvl = LOG_LVL_ERR;
    } else if (dslink_strcasestr(level, "warn") != NULL) {
        dslink_log_lvl = LOG_LVL_WARN;
    } else if (dslink_strcasestr(level, "info") != NULL) {
        dslink_log_lvl = LOG_LVL_INFO;
#ifndef NDEBUG
    } else if (dslink_strcasestr(level, "debug") != NULL) {
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
