#include "iproto_private.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

iproto_logmask_t iproto_logmask = LOG_INFO;

static iproto_logfunc_t *iproto_logfunc = NULL;
static char *logbuf = NULL;
static size_t logbuf_size = 1024;

static char *loglevel_str[LOG_DEBUG + 1] = {
    [LOG_ERROR] = "error",
    [LOG_WARNING] = "warning",
    [LOG_INFO] = "info",
    [LOG_DEBUG] = "debug"
};

void iproto_set_logmask(iproto_logmask_t mask) {
    iproto_logmask = mask;
}

void iproto_set_logfunc(iproto_logfunc_t func) {
    iproto_logfunc = func;
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
    if (iproto_logfunc) {
        if (!logbuf)
            logbuf = malloc(logbuf_size);
        va_start(ap, format);
        size_t len = vsnprintf(logbuf, logbuf_size, format, ap);
        va_end(ap);
        if (len >= logbuf_size || len == -1) {
            logbuf_size = len + 1;
            logbuf = realloc(logbuf, logbuf_size);
            va_start(ap, format);
            len = vsnprintf(logbuf, logbuf_size, format, ap);
            va_end(ap);
        }
        if (len < logbuf_size && len != -1) {
            iproto_logfunc(mask, logbuf);
            return;
        }
    }
    va_start(ap, format);
    iproto_util_log_prefix(mask, format, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void iproto_util_log_data(iproto_logmask_t mask, void *data, size_t length, const char *format, ...) {
    va_list ap;
    if (iproto_logfunc) {
        if (!logbuf)
            logbuf = malloc(logbuf_size);
        va_start(ap, format);
        size_t len = vsnprintf(logbuf, logbuf_size, format, ap);
        va_end(ap);
        size_t datalen = 24 + length * 3;
        if (len + datalen >= logbuf_size || len == -1) {
            logbuf_size = len + datalen + 1;
            logbuf = realloc(logbuf, logbuf_size);
            va_start(ap, format);
            len = vsnprintf(logbuf, logbuf_size, format, ap);
            va_end(ap);
        }
        if (len + datalen < logbuf_size && len != -1) {
            char *buf = logbuf + len;
            size_t bufsize = logbuf_size - len;
            len = snprintf(buf, bufsize, ": [%zu]", length);
            for (int i = 0; i < length; i++) {
                buf += len;
                bufsize -=len;
                len = snprintf(buf, bufsize, " %02x", ((unsigned char *)data)[i]);
            }
            iproto_logfunc(mask, logbuf);
            return;
        }
    }
    va_start(ap, format);
    iproto_util_log_prefix(mask, format, ap);
    va_end(ap);
    fprintf(stderr, ": [%zu]", length);
    for (int i = 0; i < length; i++) {
        fprintf(stderr, " %02x", ((unsigned char *)data)[i]);
    }
    fprintf(stderr, "\n");
}
