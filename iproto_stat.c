#include "iproto_private.h"

#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include "khash.h"

static time_t flush_time = 0;
static time_t flush_interval = 15;

static iproto_stat_callback_t *stat_callback = NULL;

KHASH_MAP_INIT_STR(iproto_stats, iproto_stat_t *);
static khash_t(iproto_stats) *stats = NULL;

KHASH_MAP_INIT_INT(iproto_stat_data, iproto_stat_data_t *);

struct iproto_stat {
    char *type;
    char *server;
    char *key;
    khash_t(iproto_stat_data) *data;
};

void iproto_stat_set_flush_interval(time_t interval) {
    flush_interval = interval;
}

void iproto_stat_set_callback(iproto_stat_callback_t *callback) {
    stat_callback = callback;
}

iproto_stat_t *iproto_stat_init(const char *type, const char *server) {
    if (!stats)
        stats = kh_init(iproto_stats, NULL, realloc);
    iproto_stat_t *stat = malloc(sizeof(*stat));
    stat->type = strdup(type);
    if (server) {
        stat->server = strdup(server);
        size_t typelen = strlen(type);
        size_t serverlen = strlen(server);
        stat->key = malloc(typelen + serverlen + 2);
        memcpy(stat->key, type, typelen + 1);
        stat->key[typelen] = ':';
        memcpy(stat->key + typelen + 1, server, serverlen + 1);
    } else {
        stat->server = NULL;
        stat->key = strdup(type);
    }
    stat->data = kh_init(iproto_stat_data, NULL, realloc);
    int ret;
    khiter_t k = kh_put(iproto_stats, stats, stat->key, &ret);
    assert(ret);
    kh_value(stats, k) = stat;
    return stat;
}

static void iproto_stat_send(iproto_stat_t *stat) {
    khiter_t k;
    foreach (stat->data, k) {
        iproto_error_t error = kh_key(stat->data, k);
        iproto_stat_data_t *entry = kh_value(stat->data, k);
        iproto_log(LOG_DEBUG | LOG_STAT, "stat: %s %s: %d.%06d [%d]", stat->key, iproto_error_string(error), entry->wallclock.tv_sec, entry->wallclock.tv_usec, entry->count);
        iproto_stat_graphite_send(stat->type, stat->server, error, entry);
        if (stat_callback)
            (*stat_callback)(stat->type, stat->server, error, entry);
        free(entry);
    }
    kh_clear(iproto_stat_data, stat->data);
}

void iproto_stat_free(iproto_stat_t *stat) {
    iproto_stat_send(stat);
    iproto_stat_graphite_flush();
    khiter_t k = kh_get(iproto_stats, stats, stat->key);
    assert(k != kh_end(stats));
    kh_del(iproto_stats, stats, k);
    if (kh_size(stats) == 0) {
        kh_destroy(iproto_stats, stats);
        stats = NULL;
    }
    free(stat->type);
    free(stat->server);
    free(stat->key);
    kh_destroy(iproto_stat_data, stat->data);
    free(stat);
}

void iproto_stat_flush(void) {
    if (stats) {
        khiter_t k;
        foreach (stats, k) {
            iproto_stat_t *stat = kh_value(stats, k);
            iproto_stat_send(stat);
        }
    }
    iproto_stat_graphite_flush();
    flush_time = 0;
}

static void iproto_stat_maybe_flush(void) {
    if (flush_time) {
        if (time(NULL) >= flush_time) {
            iproto_stat_flush();
        }
    } else {
        flush_time = time(NULL) + flush_interval;
    }
}

void iproto_stat_insert_duration(iproto_stat_t *stat, iproto_error_t error, struct timeval *duration) {
    iproto_stat_maybe_flush();
    khiter_t k = kh_get(iproto_stat_data, stat->data, error);
    if (k == kh_end(stat->data)) {
        int ret;
        k = kh_put(iproto_stat_data, stat->data, error, &ret);
        iproto_stat_data_t *entry = malloc(sizeof(*entry));
        memset(entry, 0, sizeof(*entry));
        time(&entry->registered);
        kh_value(stat->data, k) = entry;
    }
    iproto_stat_data_t *entry = kh_value(stat->data, k);
    timeradd(&entry->wallclock, duration, &entry->wallclock);
    entry->count++;
}

void iproto_stat_insert(iproto_stat_t *stat, iproto_error_t error, struct timeval *start_time) {
    struct timeval end;
    gettimeofday(&end, NULL);
    struct timeval duration;
    timersub(&end, start_time, &duration);
    iproto_stat_insert_duration(stat, error, &duration);
}
