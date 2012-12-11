#include "iproto_private.h"

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define GRAPHITE_MAX_SIZE 1024
int graphite_fd = -1;
static const char *graphite_prefix = NULL;
static char graphite_buffer[GRAPHITE_MAX_SIZE + 1];
static char *graphite_current = graphite_buffer;

iproto_error_t iproto_stat_graphite_set(const char *host, short port, const char *prefix) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (he && he->h_addrtype == AF_INET) {
            memcpy(&addr.sin_addr.s_addr, he->h_addr_list[0], sizeof(addr.sin_addr.s_addr));
        } else {
            return ERR_CODE_HOST_UNKNOWN;
        }
    }
    addr.sin_port = htons(port);
    if (graphite_fd >= 0)
        close(graphite_fd);
    graphite_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (graphite_fd < 0)
        return ERR_CODE_CONNECT_ERR;
    if (connect(graphite_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0)
        return ERR_CODE_CONNECT_ERR;
    graphite_prefix = prefix;
    return ERR_CODE_OK;
}

static void iproto_stat_graphite_printf(const char *format, ...) {
    int maxlen = &graphite_buffer[GRAPHITE_MAX_SIZE] - graphite_current;
    for (int t = 0; t < 2; t++) {
        va_list ap;
        va_start(ap, format);
        int len = vsnprintf(graphite_current, maxlen, format, ap);
        va_end(ap);
        if (len > maxlen) {
            iproto_stat_graphite_flush();
            assert(len <= GRAPHITE_MAX_SIZE);
        } else {
            graphite_current += len;
            break;
        }
    }
}

static char *iproto_stat_graphite_quote_key(char *key) {
    for (char *c = key; *c; c++) {
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9'))) *c = '_';
    }
    return key;
}

void iproto_stat_graphite_send(const char *type, const char *server, iproto_error_t error, iproto_stat_data_t *data) {
    if (graphite_fd < 0) return;
    char *graphite_key;
    if (server) {
        size_t typelen = strlen(type);
        size_t serverlen = strlen(server);
        graphite_key = malloc(typelen + serverlen + 2);
        memcpy(graphite_key, type, typelen + 1);
        iproto_stat_graphite_quote_key(graphite_key);
        graphite_key[typelen] = '.';
        char *skey = graphite_key + typelen + 1;
        memcpy(skey, server, serverlen + 1);
        iproto_stat_graphite_quote_key(skey);
    } else {
        graphite_key = iproto_stat_graphite_quote_key(strdup(type));
    }
    char *error_str = iproto_stat_graphite_quote_key(strdup(iproto_error_string(error)));
    iproto_stat_graphite_printf("%s.%s.%s.wallclock %d.%06d %d\n", graphite_prefix, graphite_key, error_str, data->wallclock.tv_sec, data->wallclock.tv_usec, data->registered);
    iproto_stat_graphite_printf("%s.%s.%s.count %d %d\n", graphite_prefix, graphite_key, error_str, data->count, data->registered);
    free(error_str);
    free(graphite_key);
}

void iproto_stat_graphite_flush(void) {
    if (graphite_fd < 0) return;
    if (graphite_current == graphite_buffer) return;
    *graphite_current = '\0';
    iproto_log(LOG_DEBUG | LOG_GRAPHITE, "send stat to graphite: [%s]", graphite_buffer);
    if (write(graphite_fd, graphite_buffer, graphite_current - graphite_buffer) < 0) {
        iproto_log(LOG_WARNING | LOG_GRAPHITE, "failed to send stat to graphite: %m");
    }
    graphite_current = graphite_buffer;
}
