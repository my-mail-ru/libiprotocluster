#include "iproto_private.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/queue.h>
#include "khash.h"

KHASH_INIT(server_shards, iproto_shard_t *, int, 1, kh_req_hash_func, kh_req_hash_equal);
KHASH_INIT(request_message, struct iproto_request_t *, iproto_message_t *, 1, kh_req_hash_func, kh_req_hash_equal);
KHASH_MAP_INIT_STR(hp_servers, iproto_server_t *);

struct iproto_server {
    char *hostport;
    char *host;
    int port;
    int refcnt;
    struct iproto_connection_t *connection;
    khash_t(server_shards) *shards;
    khash_t(request_message) *in_progress;
    TAILQ_HEAD(failed_messages, message_entry) failed;
    enum {
        NotConnected = 0,
        ConnectInProgress,
        Connected
    } status;
    short events;
    struct timeval last_error_time;
    iproto_stat_t *request_stat;
    iproto_stat_t *poll_stat;
    struct timeval poll_start_time;
};

struct message_entry {
    iproto_message_t *message;
    TAILQ_ENTRY(message_entry) link;
};

static khash_t(hp_servers) *server_pool = NULL;
static struct memory_arena_pool_t *arena_pool = NULL;
static int arena_pool_refcnt = 0;

#define iproto_server_log(server, mask, format, ...) \
    iproto_log(mask, "server %s:%d: " format, server->host, server->port, ##__VA_ARGS__)

#define iproto_server_log_data(server, mask, data, size, format, ...) \
    iproto_log_data(mask, data, size, "server %s:%d: " format, server->host, server->port, ##__VA_ARGS__)

iproto_server_t *iproto_server_init(char *host, int port) {
    if (!server_pool)
        server_pool = kh_init(hp_servers, NULL, realloc);
    char hostport[256];
    snprintf(hostport, 256, "%s:%d", host, port);
    khiter_t k = kh_get(hp_servers, server_pool, hostport);
    if (k != kh_end(server_pool)) {
        iproto_server_t *server = kh_value(server_pool, k);
        assert(strcmp(server->host, host) == 0 && server->port == port);
        server->refcnt++;
        return server;
    }
    iproto_server_t *server = malloc(sizeof(iproto_server_t));
    memset(server, 0, sizeof(iproto_server_t));
    server->hostport = strdup(hostport);
    server->host = strdup(host);
    server->port = port;

    if (arena_pool_refcnt++ == 0)
        arena_pool = map_alloc(realloc, 16, 64 * 1024);
    server->connection = li_conn_init(realloc, arena_pool, NULL);
    server->shards = kh_init(server_shards, NULL, realloc);
    server->in_progress = kh_init(request_message, NULL, realloc);
    TAILQ_INIT(&server->failed);
    server->request_stat = iproto_stat_init("request", hostport);
    server->poll_stat = iproto_stat_init("poll", hostport);
    server->refcnt = 1;
    int ret;
    k = kh_put(hp_servers, server_pool, server->hostport, &ret);
    if (!ret) return NULL;
    kh_value(server_pool, k) = server;
    return server;
}

static void iproto_server_close(iproto_server_t *server) {
    if (server->status != NotConnected) {
        li_close(server->connection);
        server->status = NotConnected;
        iproto_server_log(server, LOG_INFO | LOG_CONNECT, "disconnected");
    }
}

void iproto_server_free(iproto_server_t *server) {
    if (--server->refcnt == 0) {
        if (server->status != NotConnected)
            iproto_server_close(server);
        li_free(server->connection);
        kh_destroy(request_message, server->in_progress);
        kh_destroy(server_shards, server->shards);
        char hostport[256];
        snprintf(hostport, 256, "%s:%d", server->host, server->port);
        khiter_t k = kh_get(hp_servers, server_pool, hostport);
        if (k != kh_end(server_pool)) {
            assert(kh_value(server_pool, k) == server);
            kh_del(hp_servers, server_pool, k);
        }
        iproto_stat_free(server->request_stat);
        iproto_stat_free(server->poll_stat);
        free(server->hostport);
        free(server->host);
        free(server);
        if (--arena_pool_refcnt == 0)
            map_free(arena_pool);
    }
}

void iproto_server_refcnt_inc(iproto_server_t *server) {
    server->refcnt++;
}

const char *iproto_server_hostport(iproto_server_t *server) {
    return server->hostport;
}

void iproto_server_add_to_shard(iproto_server_t *server, iproto_shard_t *shard) {
    khiter_t k = kh_get(server_shards, server->shards, shard);
    if (k == kh_end(server->shards)) {
        int ret;
        k = kh_put(server_shards, server->shards, shard, &ret);
        kh_value(server->shards, k) = 1;
    } else {
        kh_value(server->shards, k)++;
    }
    server->refcnt++;
}

void iproto_server_remove_from_shard(iproto_server_t *server, iproto_shard_t *shard) {
    khiter_t k = kh_get(server_shards, server->shards, shard);
    if (k == kh_end(server->shards)) return;
    if (--kh_value(server->shards, k) == 0) kh_del(server_shards, server->shards, k);
    iproto_server_free(server);
}

bool iproto_server_is_active(iproto_server_t *server, const struct timeval *server_freeze) {
    if (!timerisset(&server->last_error_time)) return true;
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timeval diff;
    timersub(&now, &server->last_error_time, &diff);
    return timercmp(&diff, server_freeze, >=);
}

static void iproto_server_connect(iproto_server_t *server) {
    iproto_error_t status = li_connect(server->connection, server->host, server->port, LIBIPROTO_OPT_NONBLOCK);
    switch (status) {
        case ERR_CODE_OK:
            server->status = Connected;
            memset(&server->last_error_time, 0, sizeof(struct timeval));
            iproto_server_log(server, LOG_INFO | LOG_CONNECT, "connected");
            break;
        case ERR_CODE_CONNECT_IN_PROGRESS:
            server->status = ConnectInProgress;
            server->events = POLLOUT;
            iproto_server_log(server, LOG_DEBUG | LOG_CONNECT, "connecting");
            break;
        case ERR_CODE_CONNECT_ERR:
            server->status = NotConnected;
            iproto_server_handle_error(server, status);
            break;
        default:
            iproto_server_log(server, LOG_ERROR | LOG_IO, "unknown li_connect() error code: %u", status);
            abort();
    }
}

int iproto_server_get_fd(iproto_server_t *server) {
    if (server->status == NotConnected) iproto_server_connect(server);
    return li_get_fd(server->connection);
}

void iproto_server_send(iproto_server_t *server, iproto_message_t *message) {
    void *data;
    size_t size;
    uint32_t code = iproto_message_get_request(message, &data, &size);
    struct iproto_request_t *request = li_req_init(server->connection, code, data, size);
    assert(request); // TODO Handle NULL result from this function
    iproto_server_log_data(server, LOG_DEBUG | LOG_DATA, data, size, "send request %p (code = %d)", request, code);
    int ret;
    khiter_t k = kh_put(request_message, server->in_progress, request, &ret);
    assert(ret); // TODO Handle if (!ret) ...
    kh_value(server->in_progress, k) = message;
    server->events |= POLLOUT;
    iproto_message_insert_request(message, server, request);
}

iproto_message_t *iproto_server_recv(iproto_server_t *server) {
    struct message_entry *entry = TAILQ_FIRST(&server->failed);
    if (entry) {
        TAILQ_REMOVE(&server->failed, entry, link);
        iproto_message_t *message = entry->message;
        free(entry);
        return message;
    }
    iproto_message_t *message;
    struct iproto_request_t *request;
    while (1) {
        request = li_get_ready_reqs(server->connection);
        if (!request) return NULL;
        size_t size;
        void *data = li_req_response_data(request, &size);
        iproto_server_log_data(server, LOG_DEBUG | LOG_DATA, data, size, "recv response %p", request);
        khiter_t k = kh_get(request_message, server->in_progress, request);
        if (k != kh_end(server->in_progress)) {
            message = kh_value(server->in_progress, k);
            kh_del(request_message, server->in_progress, k);
            break;
        } else {
            li_req_free(request);
        }
    }
    // TODO Avoid copy maybe?
    size_t size;
    void *data = li_req_response_data(request, &size);
    iproto_message_set_response(message, ERR_CODE_OK, data, size);
    iproto_message_remove_request(message, server, request);
    li_req_free(request);
    return message;
}

static void iproto_server_mark_error(iproto_server_t *server) {
    gettimeofday(&server->last_error_time, NULL);
    khiter_t k;
    foreach (server->shards, k) {
        iproto_shard_move_server_to_tail(kh_key(server->shards, k), server);
    }
}

void iproto_server_prepare_poll(iproto_server_t *server, struct pollfd *pfd) {
    if (!timerisset(&server->poll_start_time))
        gettimeofday(&server->poll_start_time, NULL);
    pfd->fd = li_get_fd(server->connection);
    pfd->events = server->events;
    pfd->revents = 0;
    iproto_server_log(server, LOG_DEBUG | LOG_POLL, "prepare poll(): 0x%x", pfd->events);
}

bool iproto_server_handle_poll(iproto_server_t *server, short revents) {
    iproto_server_log(server, LOG_DEBUG | LOG_POLL, "handle poll(): 0x%x", revents);
    if (revents & POLLERR) {
        iproto_server_handle_error(server, ERR_CODE_CONNECT_ERR);
        return true;
    }
    if (revents & POLLIN) {
        iproto_server_log(server, LOG_DEBUG | LOG_IO, "reading data");
        iproto_error_t status = li_read(server->connection);
        switch (status) {
            case ERR_CODE_CONNECT_ERR:
                iproto_server_log(server, LOG_ERROR | LOG_IO, "read error");
                iproto_server_handle_error(server, status);
                break;
            case ERR_CODE_OK:
                iproto_server_log(server, LOG_DEBUG | LOG_IO, "not all data read");
                server->events |= POLLIN;
                break;
            case ERR_CODE_NOTHING_TO_DO:
                iproto_server_log(server, LOG_DEBUG | LOG_IO, "all data read");
                server->events &= ~POLLIN;
                break;
            default:
                iproto_server_log(server, LOG_ERROR | LOG_IO, "unknown li_read() error code: %u", status);
                abort();
        }
    }
    if (revents & POLLOUT) {
        if (server->status == Connected) {
            iproto_server_log(server, LOG_DEBUG | LOG_IO, "writting data");
            iproto_error_t status = li_write(server->connection);
            switch (status) {
                case ERR_CODE_CONNECT_ERR:
                    iproto_server_log(server, LOG_ERROR | LOG_IO, "write error");
                    iproto_server_handle_error(server, status);
                    break;
                case ERR_CODE_OK:
                    iproto_server_log(server, LOG_DEBUG | LOG_IO, "not all data written");
                    server->events |= POLLOUT;
                    server->events |= POLLIN;
                    break;
                case ERR_CODE_NOTHING_TO_DO:
                    iproto_server_log(server, LOG_DEBUG | LOG_IO, "all data written");
                    server->events &= ~POLLOUT;
                    server->events |= POLLIN;
                    break;
                default:
                    iproto_server_log(server, LOG_ERROR | LOG_IO, "unknown li_write() error code: %u", status);
                    abort();
            }
        } else {
            iproto_server_connect(server);
        }
    }
    if (server->events == 0) {
        iproto_stat_insert(server->poll_stat, ERR_CODE_OK, &server->poll_start_time);
        memset(&server->poll_start_time, 0, sizeof(struct timeval));
        return true;
    } else {
        return false;
    }
}

void iproto_server_handle_error(iproto_server_t *server, iproto_error_t error) {
    iproto_server_log(server, LOG_ERROR, "%s [%d]", iproto_error_string(error), error);
    iproto_stat_insert(server->poll_stat, error, &server->poll_start_time);
    memset(&server->poll_start_time, 0, sizeof(struct timeval));
    khiter_t k;
    foreach (server->in_progress, k) {
        iproto_message_t *message = kh_value(server->in_progress, k);
        iproto_message_set_response(message, error, NULL, 0);
        struct message_entry *entry = malloc(sizeof(*entry));
        entry->message = message;
        TAILQ_INSERT_TAIL(&server->failed, entry, link);
        iproto_message_remove_request(message, server, kh_key(server->in_progress, k));
    }
    kh_clear(request_message, server->in_progress);
    iproto_server_close(server);
    iproto_server_mark_error(server);
}

void iproto_server_remove_message(iproto_server_t *server, iproto_message_t *message, struct iproto_request_t *request) {
    khiter_t k = kh_get(request_message, server->in_progress, request);
    if (k != kh_end(server->in_progress)) kh_del(request_message, server->in_progress, k);
}

void iproto_server_insert_request_stat(iproto_server_t *server, iproto_error_t error, struct timeval *start_time) {
    iproto_stat_insert(server->request_stat, error, start_time);
}

void iproto_server_close_all(void) {
    if (!server_pool) return;
    khiter_t k;
    foreach (server_pool, k) {
        iproto_server_t *server = kh_value(server_pool, k);
        iproto_server_close(server);
    }
}
