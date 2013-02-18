#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/queue.h>

struct server_request {
    iproto_server_t *server;
    struct iproto_request_t *request;
    struct timeval start_time;
    TAILQ_ENTRY(server_request) link;
};

struct iproto_message {
    iproto_cluster_t *cluster;
    struct {
        uint32_t code;
        void *data;
        size_t size;
    } request;
    struct {
        iproto_error_t error;
        void *data;
        size_t size;
        bool replica;
    } response;
    iproto_message_opts_t opts;
    int tries;
    int soft_retries;
    bool is_unsafe;
    TAILQ_HEAD(message_requests, server_request) requests;
    iproto_message_ev_t *ev;
};

iproto_message_t *iproto_message_init(int code, void *data, size_t size) {
    iproto_message_t *message = malloc(sizeof(iproto_message_t));
    memset(message, 0, sizeof(iproto_message_t));
    message->opts.from = FROM_MASTER;
    message->opts.early_timeout.tv_usec = 50000;
    message->opts.timeout.tv_usec = 500000;
    message->opts.max_tries = 3;
    message->opts.retry = RETRY_SAFE;
    message->opts.soft_retry_delay_min.tv_usec = 100000;
    message->opts.soft_retry_delay_max.tv_usec = 900000;
    message->response.error = ERR_CODE_REQUEST_IN_PROGRESS;
    TAILQ_INIT(&message->requests);
    message->request.code = code;
    message->request.data = data;
    message->request.size = size;
    message->ev = iproto_message_ev_init(message);
    return message;
}

void iproto_message_free(iproto_message_t *message) {
    assert(TAILQ_FIRST(&message->requests) == NULL);
    iproto_message_ev_free(message->ev);
    if (message->response.data) free(message->response.data);
    free(message);
}

void iproto_message_set_cluster(iproto_message_t *message, iproto_cluster_t *cluster) {
    message->cluster = cluster;
}

iproto_cluster_t *iproto_message_get_cluster(iproto_message_t *message) {
    return message->cluster;
}

iproto_message_ev_t *iproto_message_get_ev(iproto_message_t *message) {
    return message->ev;
}

iproto_message_opts_t *iproto_message_options(iproto_message_t *message) {
    return &message->opts;
}

iproto_error_t iproto_message_error(iproto_message_t *message) {
    return message->response.error;
}

void *iproto_message_response(iproto_message_t *message, size_t *size, bool *replica) {
    *replica = message->response.replica;
    *size = message->response.size;
    return message->response.data;
}

bool iproto_message_soft_retry(iproto_message_t *message, struct timeval *delay) {
    iproto_message_opts_t *opts = iproto_message_options(message);
    if (message->tries < message->opts.max_tries && opts->soft_retry_callback && opts->soft_retry_callback(message)) {
        iproto_log(LOG_DEBUG | LOG_RETRY, "soft retry");
        iproto_message_set_response(message, NULL, ERR_CODE_REQUEST_IN_PROGRESS, NULL, 0);
        message->is_unsafe = false;
        timersub(&message->opts.soft_retry_delay_max, &message->opts.soft_retry_delay_min, delay);
        double k = message->opts.max_tries > 2 ? (double)message->soft_retries / (message->opts.max_tries - 2) : 0.5;
        delay->tv_sec *= k;
        delay->tv_usec *= k;
        timeradd(&message->opts.soft_retry_delay_min, delay, delay);
        message->soft_retries++;
        return true;
    } else {
        return false;
    }
}

bool iproto_message_can_try(iproto_message_t *message) {
    if (TAILQ_FIRST(&message->requests) == NULL) {
        return (!((message->opts.retry & RETRY_SAFE) && message->is_unsafe))
            && ++message->tries <= message->opts.max_tries;
    } else {
        return false;
    }
}

bool iproto_message_retry_same(iproto_message_t *message) {
    return (message->opts.retry & RETRY_SAME) && message->is_unsafe;
}

void iproto_message_insert_request(iproto_message_t *message, iproto_server_t *server, struct iproto_request_t *request) {
    struct server_request *entry = malloc(sizeof(*entry));
    entry->server = server;
    entry->request = request;
    gettimeofday(&entry->start_time, NULL);
    TAILQ_INSERT_TAIL(&message->requests, entry, link);
}

void iproto_message_remove_request(iproto_message_t *message, iproto_server_t *server, struct iproto_request_t *request) {
    int count = 0;
    struct server_request *remove = NULL;
    struct server_request *entry;
    TAILQ_FOREACH (entry, &message->requests, link) {
        if (entry->request == request) {
            assert(entry->server == server);
            remove = entry;
            count++;
        }
    }
    assert(count == 1);
    TAILQ_REMOVE(&message->requests, remove, link);
    iproto_server_insert_request_stat(server, message->response.error, &remove->start_time);
    free(remove);
}

int iproto_message_clear_requests(iproto_message_t *message, iproto_error_t error) {
    int count = 0;
    struct server_request *entry;
    while ((entry = TAILQ_FIRST(&message->requests))) {
        iproto_server_remove_message(entry->server, message, entry->request, error);
        TAILQ_REMOVE(&message->requests, entry, link);
        iproto_server_insert_request_stat(entry->server, error, &entry->start_time);
        free(entry);
        count++;
    }
    return count;
}

bool iproto_message_in_progress(iproto_message_t *message) {
    return TAILQ_FIRST(&message->requests) != NULL;
}

struct timeval *iproto_message_request_start_time(iproto_message_t *message, iproto_server_t *server) {
    int count = 0;
    struct timeval *start_time = NULL;
    struct server_request *entry;
    TAILQ_FOREACH (entry, &message->requests, link) {
        if (entry->server == server) {
            start_time = &entry->start_time;
            count++;
        }
    }
    assert(count == 1);
    return start_time;
}

uint32_t iproto_message_get_request(iproto_message_t *message, void **data, size_t *size) {
    *data = message->request.data;
    *size = message->request.size;
    return message->request.code;
}

void iproto_message_set_response(iproto_message_t *message, iproto_server_t *server, iproto_error_t error, void *data, size_t size) {
    message->response.error = error;
    if (data != NULL) {
        message->response.data = realloc(message->response.data, size);
        memcpy(message->response.data, data, size);
        message->response.size = size;
    } else {
        if (message->response.data)
            free(message->response.data);
        message->response.data = NULL;
        message->response.size = 0;
    }
    message->response.replica = server ? iproto_cluster_is_server_replica(message->cluster, message, server) : false;
    struct server_request *entry;
    TAILQ_FOREACH (entry, &message->requests, link) {
        if (li_req_state(entry->request) != ERR_CODE_REQUEST_IN_PROGRESS)
            message->is_unsafe = true;
    }
    iproto_message_ev_stop_timer(message->ev);
}
