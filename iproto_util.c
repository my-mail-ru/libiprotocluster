#include "iproto_private.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

iproto_logmask_t iproto_logmask = LOG_INFO;

static char *loglevel_str[LOG_DEBUG + 1] = {
    [LOG_ERROR] = "error",
    [LOG_WARNING] = "warning",
    [LOG_INFO] = "info",
    [LOG_DEBUG] = "debug"
};

void iproto_set_logmask(iproto_logmask_t mask) {
    iproto_logmask = mask;
}

void iproto_util_log_prefix(iproto_logmask_t mask, const char *format, va_list ap) {
    char timestr[20];
    struct tm loctime;
    struct timeval now;
    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &loctime);
    strftime(timestr, sizeof(timestr), "%F %T", &loctime);
    fprintf(stderr, "%d [%s.%06ld] %s: ", getpid(), timestr, now.tv_usec, loglevel_str[mask & LOG_LEVEL]);
    vfprintf(stderr, format, ap);
}

void iproto_util_log(iproto_logmask_t mask, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    iproto_util_log_prefix(mask, format, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void iproto_util_log_data(iproto_logmask_t mask, void *data, size_t length, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    iproto_util_log_prefix(mask, format, ap);
    va_end(ap);
    fprintf(stderr, ": [%zu]", length);
    for (int i = 0; i < length; i++) {
        fprintf(stderr, " %02x", ((unsigned char *)data)[i]);
    }
    fprintf(stderr, "\n");
}
