#ifndef IPROTO_UTIL_H_INCLUDED
#define IPROTO_UTIL_H_INCLUDED

#include <stdarg.h>

void iproto_util_log_prefix(iproto_logmask_t mask, const char *format, va_list ap);
void iproto_util_log(iproto_logmask_t mask, const char *format, ...);
void iproto_util_log_data(iproto_logmask_t mask, void *data, size_t length, const char *format, ...);

#endif
