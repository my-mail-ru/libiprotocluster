#include "iproto_private.h"

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
    bool is_unsafe;
    TAILQ_HEAD(message_requests, server_request) requests;
};

iproto_message_t *iproto_message_init(int code, void *data, size_t size) {
    iproto_message_t *message = malloc(sizeof(iproto_message_t));
    memset(message, 0, sizeof(iproto_message_t));
    message->opts.from = FROM_MASTER;
    message->opts.max_tries = 3;
    message->opts.retry = RETRY_SAFE;
    message->response.error = ERR_CODE_REQUEST_IN_PROGRESS;
    TAILQ_INIT(&message->requests);
    message->request.code = code;
    message->request.data = data;
    message->request.size = size;
    return message;
}

void iproto_message_free(iproto_message_t *message) {
    assert(TAILQ_FIRST(&message->requests) == NULL);
    if (message->response.data) free(message->response.data);
    free(message);
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

bool iproto_message_can_try(iproto_message_t *message, bool is_early_retry) {
    if (is_early_retry) {
        return message->opts.retry & RETRY_EARLY;
    } else if (TAILQ_FIRST(&message->requests) == NULL) {
        return (!((message->opts.retry & RETRY_SAFE) && message->is_unsafe))
            && ++message->tries <= message->opts.max_tries;
    } else {
        return false;
    }
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

int iproto_message_clear_requests(iproto_message_t *message) {
    int count = 0;
    struct server_request *entry;
    while ((entry = TAILQ_FIRST(&message->requests))) {
        iproto_server_remove_message(entry->server, message, entry->request);
        TAILQ_REMOVE(&message->requests, entry, link);
        iproto_server_insert_request_stat(entry->server, ERR_CODE_LOSE_EARLY_RETRY, &entry->start_time);
        free(entry);
        count++;
    }
    return count;
}

uint32_t iproto_message_get_request(iproto_message_t *message, void **data, size_t *size) {
    *data = message->request.data;
    *size = message->request.size;
    return message->request.code;
}

void iproto_message_set_response(iproto_message_t *message, iproto_error_t error, void *data, size_t size) {
    message->response.error = error;
    if (data != NULL) {
        message->response.data = malloc(size);
        memcpy(message->response.data, data, size);
        message->response.size = size;
    } else {
        if (message->response.data)
            free(message->response.data);
        message->response.data = NULL;
        message->response.size = 0;
    }
    struct server_request *entry;
    TAILQ_FOREACH (entry, &message->requests, link) {
        if (li_req_state(entry->request) != ERR_CODE_REQUEST_IN_PROGRESS)
            message->is_unsafe = true;
    }
}

void iproto_message_set_replica(iproto_message_t *message, bool is_replica) {
    message->response.replica = is_replica;
}
