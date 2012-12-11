#include "iproto_private.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <poll.h>
#include "khash.h"

struct iproto_cluster {
    struct {
        iproto_shard_t **a;
        int n;
    } shards;
    iproto_opts_t opts;
    iproto_stat_t *stat;
};

KHASH_MAP_INIT_INT(fd_server, iproto_server_t *);

static bool initialized = false;
static iproto_stat_t *stat = NULL;
static int stat_refcnt = 0;

static void iproto_atfork_child(void) {
    iproto_log(LOG_DEBUG | LOG_FORK, "fork() detected");
    iproto_server_close_all();
}

void iproto_initialize(void) {
    if (initialized) return;
    ERRCODE_ADD(ERRCODE_DESCRIPTION, IPROTO_ALL_ERROR_CODES);
    pthread_atfork(NULL, NULL, iproto_atfork_child);
    initialized = true;
}

void iproto_opts_init(iproto_opts_t *opts) {
    iproto_initialize();
    memset(opts, 0, sizeof(iproto_opts_t));
    opts->request_timeout.tv_sec = 2;
    opts->first_timeout.tv_usec = 50000;
    opts->server_freeze.tv_sec = 15;
    opts->max_tries = 3;
    opts->retry = RETRY_ANOTHER;
}

void iproto_opts_free(iproto_opts_t *opts) {
}

iproto_t *iproto_init(void) {
    iproto_t *iproto = malloc(sizeof(iproto_t));
    memset(iproto, 0, sizeof(iproto_t));
    iproto_opts_init(&iproto->opts);
    if (stat_refcnt++ == 0)
        stat = iproto_stat_init("call", NULL);
    return iproto;
}

void iproto_free(iproto_t *iproto) {
    for (int i = 0; i < iproto->shards.n; i++) {
        iproto_shard_free(iproto->shards.a[i]);
    }
    if (--stat_refcnt == 0)
        iproto_stat_free(stat);
    free(iproto->shards.a);
    free(iproto);
}

void iproto_add_shard(iproto_t *iproto, iproto_shard_t *shard) {
    iproto->shards.a = realloc(iproto->shards.a, ++iproto->shards.n * sizeof(iproto_shard_t *));
    iproto->shards.a[iproto->shards.n - 1] = shard;
}

static iproto_shard_t *iproto_get_shard(iproto_t *iproto, iproto_message_t *message) {
    unsigned shard_num = iproto_message_options(message)->shard_num;
    if (shard_num == 0 && iproto->shards.n == 1) {
        shard_num = 1;
    } else if (shard_num < 1 || shard_num > iproto->shards.n) {
        iproto_message_set_response(message, ERR_CODE_INVALID_SHARD_NUM, NULL, 0);
        return NULL;
    }
    return iproto->shards.a[shard_num - 1];
}

static iproto_server_t *iproto_get_server(iproto_t *iproto, iproto_message_t *message, iproto_server_t **not_servers, int n_not_servers) {
    iproto_shard_t *shard = iproto_get_shard(iproto, message);
    if (!shard) return NULL;
    return iproto_shard_get_server(shard, message, not_servers, n_not_servers, &iproto->opts.server_freeze);
}

static bool iproto_is_server_replica(iproto_t *iproto, iproto_message_t *message, iproto_server_t *server) {
    iproto_shard_t *shard = iproto_get_shard(iproto, message);
    if (!shard) return false;
    return iproto_shard_is_server_replica(shard, server);
}

static int iproto_dispatch_message(iproto_t *iproto, iproto_message_t *message, khash_t(fd_server) *servers, iproto_server_t *not_server, bool finish) {
    if (iproto_message_error(message) == ERR_CODE_OK) {
        return -iproto_message_clear_requests(message);
    } else if (finish) {
        return 0;
    } else if (!iproto_message_can_try(message, not_server != NULL)) {
        return 0;
    }
    iproto_server_t *srvs[3];
    memset(&srvs, 0, 3 * sizeof(iproto_server_t *));
    srvs[0] = not_server;
    int count = 0;
    for (int t = (not_server ? 1 : 0); t < (not_server ? 3 : 1); t++) {
        iproto_server_t *server = iproto_get_server(iproto, message, srvs, t);
        if (server) {
            int fd = iproto_server_get_fd(server);
            assert(fd > 0);
            int ret;
            khiter_t k = kh_put(fd_server, servers, fd, &ret);
            if (ret) kh_value(servers, k) = server;
            else assert(kh_value(servers, k) == server);
            iproto_server_send(server, message);
            srvs[t] = server;
            count++;
        }
    }
    if (not_server) {
        iproto_log(LOG_WARNING | LOG_RETRY, "early retry for %s - %s and %s", iproto_server_hostport(srvs[0]),
            srvs[1] ? iproto_server_hostport(srvs[1]) : "nothing",
            srvs[2] ? iproto_server_hostport(srvs[2]) : "nothing");
    }
    return count;
}

static int iproto_postprocess_server(iproto_t *iproto, iproto_server_t *server, khash_t(fd_server) *servers, bool finish) {
    int wait = 0;
    iproto_message_t *message;
    while ((message = iproto_server_recv(server))) {
        iproto_message_set_replica(message, iproto_is_server_replica(iproto, message, server));
        wait--;
        wait += iproto_dispatch_message(iproto, message, servers, NULL, finish);
    }
    return wait;
}

void iproto_bulk(iproto_t *iproto, iproto_message_t **messages, int nmessages, iproto_opts_t *opts) {
    if (!opts) opts = &iproto->opts;
    iproto_error_t error = ERR_CODE_OK;
    bool is_first_timeout = true;
    struct timeval timeout;
    memcpy(&timeout, &opts->first_timeout, sizeof(struct timeval));
    struct timeval begin;
    gettimeofday(&begin, NULL);
    int wait = 0;
    khash_t(fd_server) *servers = kh_init(fd_server, NULL, realloc);
    for (int i = 0; i < nmessages; i++) {
        wait += iproto_dispatch_message(iproto, messages[i], servers, NULL, false);
    }
    struct timeval start;
    memcpy(&start, &begin, sizeof(struct timeval));
    struct pollfd *fds = NULL;
    while (wait) {
        assert(wait > 0);
        fds = realloc(fds, kh_size(servers) * sizeof(struct pollfd));
        nfds_t nfds = 0;
        for (khiter_t k = kh_begin(servers); k != kh_end(servers); k++) {
            if (kh_exist(servers, k)) {
                iproto_server_t *server = kh_value(servers, k);
                iproto_server_prepare_poll(server, &fds[nfds]);
                nfds++;
            }
        }
        int timeoutms = timeout.tv_sec * 1000 + (int)ceil(timeout.tv_usec / 1000.);
        if (timeoutms < 0) timeoutms = 0;
        iproto_log(LOG_DEBUG | LOG_POLL, "poll(%d, %dms), wait %d messages", nfds, timeoutms, wait);
        int state = poll(fds, nfds, timeoutms);
        struct timeval finish;
        gettimeofday(&finish, NULL);
        struct timeval diff;
        timersub(&finish, &start, &diff);
        timersub(&timeout, &diff, &timeout);
        memcpy(&start, &finish, sizeof(struct timeval));
        if (state > 0) {
            for (nfds_t i = 0; i < nfds; i++) {
                if (fds[i].revents) {
                    assert((fds[i].revents & POLLNVAL) == 0);
                    khiter_t k = kh_get(fd_server, servers, fds[i].fd);
                    assert(k != kh_end(servers));
                    iproto_server_t *server = kh_value(servers, k);
                    if (iproto_server_handle_poll(server, fds[i].revents))
                        kh_del(fd_server, servers, k);
                    wait += iproto_postprocess_server(iproto, server, servers, false);
                }
            }
        } else if (state == 0) {
            iproto_log(LOG_WARNING | LOG_POLL, "%s timeout", is_first_timeout ? "first" : "request");
            iproto_server_t **servers_list = malloc(kh_size(servers) * sizeof(iproto_server_t *));
            khiter_t k;
            int s = 0;
            foreach (servers, k) {
                servers_list[s] = kh_value(servers, k);
                s++;
            }
            for (int i = 0; i < s; i++) {
                iproto_server_t *server = servers_list[i];
                if (is_first_timeout) {
                    timersub(&opts->request_timeout, &opts->first_timeout, &timeout);
                    for (int j = 0; j < nmessages; j++) {
                        iproto_message_t *message = messages[j];
                        wait += iproto_dispatch_message(iproto, message, servers, server, false);
                    }
                } else {
                    kh_del(fd_server, servers, k);
                    iproto_server_handle_error(server, ERR_CODE_TIMEOUT);
                    wait += iproto_postprocess_server(iproto, server, servers, true);
                }
            }
            if (is_first_timeout) is_first_timeout = false;
            else error = ERR_CODE_TIMEOUT;
            free(servers_list);
        } else if (errno != EINTR) {
            iproto_log(LOG_ERROR | LOG_POLL, "poll error: %m");
            abort();
        }
    }
    free(fds);
    kh_destroy(fd_server, servers);
    assert(wait == 0);
    struct timeval end;
    gettimeofday(&end, NULL);
    struct timeval overall;
    timersub(&end, &begin, &overall);
    iproto_stat_insert_duration(stat, error, &overall);
    iproto_log(LOG_DEBUG | LOG_TIME, "request time: %dms.", overall.tv_sec * 1000 + (int)round(overall.tv_usec / 1000.));
}

void iproto_do(iproto_t *iproto, iproto_message_t *message, iproto_opts_t *opts) {
    iproto_bulk(iproto, &message, 1, opts);
}
