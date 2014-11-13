#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include "khash.h"

KHASH_INIT(server_ev_set, iproto_server_ev_t *, char, 0, kh_req_hash_func, kh_req_hash_equal);

typedef struct {
    iproto_message_t **messages;
    int nmessages;
    iproto_error_t *error;
} iproto_bulk_timeout_data_t;

static bool initialized = false;
static iproto_stat_t *call_stat = NULL;

static void iproto_atfork_child(void) {
    iproto_log(LOG_DEBUG | LOG_FORK, "fork() detected");
    iproto_server_close_all();
    if (EV_DEFAULT)
        ev_loop_fork(EV_DEFAULT);
}

void iproto_initialize(void) {
    if (initialized) return;
    ERRCODE_ADD(ERRCODE_DESCRIPTION, IPROTO_ALL_ERROR_CODES);
    iproto_evapi_initialize();
    pthread_atfork(NULL, NULL, iproto_atfork_child);
    initialized = true;
}

void iproto_init_globals(void) {
    call_stat = iproto_stat_init("call", NULL);
}

void iproto_free_globals(void) {
    iproto_stat_free(call_stat);
}

static void iproto_call_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void iproto_bulk_message_cb(iproto_message_t *message);

static bool iproto_send(struct ev_loop *loop, iproto_message_t *message) {
    if (iproto_message_get_cluster(message)) {
        iproto_message_ev_t *ev = iproto_message_get_ev(message);
        iproto_message_ev_start(ev, loop);
        iproto_message_ev_dispatch(ev, false);
        return true;
    } else {
        iproto_message_set_response(message, NULL, ERR_CODE_CLUSTER_NOT_SET, NULL, 0);
        return false;
    }
}

void iproto_bulk(iproto_message_t **messages, int nmessages, struct timeval *timeout) {
    iproto_stat_maybe_flush();

    struct timeval begin;
    gettimeofday(&begin, NULL);
    iproto_error_t error = ERR_CODE_OK;

    struct ev_loop *loop = EV_DEFAULT;
    ev_now_update(loop);

    ev_timer *timer = NULL;
    iproto_bulk_timeout_data_t to_data;
    if (timeout) {
        to_data.messages = malloc(sizeof(iproto_message_t *) * nmessages);
        to_data.nmessages = 0;
        to_data.error = &error;
        timer = ev_timer_new(iproto_call_timeout_cb);
        ev_timer_set(timer, timeval2ev(*timeout), 0);
        ev_timer_set_data(timer, &to_data);
        ev_timer_start(loop, timer);
    }

    int messages_in_progress = 0;
    for (int i = 0; i < nmessages; i++) {
        iproto_message_opts_t *opts = iproto_message_options(messages[i]);
        if (opts->callback == NULL) {
            opts->callback = iproto_bulk_message_cb;
            iproto_message_ev_set_data(iproto_message_get_ev(messages[i]), &messages_in_progress);
            if (iproto_send(loop, messages[i])) {
                messages_in_progress++;
                if (timeout)
                    to_data.messages[to_data.nmessages++] = messages[i];
            }
        } else {
            iproto_send(loop, messages[i]);
        }
    }

    if (messages_in_progress != 0) {
        ev_run(loop, 0);
        assert(messages_in_progress == 0);
    }

    if (timeout) {
        ev_timer_stop(loop, timer);
        ev_timer_free(timer);
        free(to_data.messages);
    }

    struct timeval end;
    gettimeofday(&end, NULL);
    struct timeval diff;
    timersub(&end, &begin, &diff);
    iproto_stat_insert_duration(call_stat, error, &diff);
    iproto_log(LOG_DEBUG | LOG_TIME, "call time: %dms.", diff.tv_sec * 1000 + (int)round(diff.tv_usec / 1000.));
}

void iproto_do(iproto_message_t *message, struct timeval *timeout) {
    iproto_bulk(&message, 1, timeout);
}

static void iproto_cancel_on_timeout(iproto_server_t *server) {
    iproto_server_ev_cancel(iproto_server_get_ev(server), ERR_CODE_TIMEOUT);
}

static void iproto_call_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_log(LOG_ERROR | LOG_EV, "call timeout");
    iproto_bulk_timeout_data_t* data = (iproto_bulk_timeout_data_t *)ev_timer_data(w);
    for (int i = 0; i < data->nmessages; i++) {
        iproto_message_while_request_server(data->messages[i], iproto_cancel_on_timeout);
    }
    *data->error = ERR_CODE_TIMEOUT;
}

static void iproto_bulk_message_cb(iproto_message_t *message) {
    iproto_message_options(message)->callback = NULL;
    iproto_message_ev_t *ev = iproto_message_get_ev(message);
    int *messages_in_progress = (int *)iproto_message_ev_data(ev);
    if (--(*messages_in_progress) == 0)
        ev_break(iproto_message_ev_loop(ev), EVBREAK_ONE);
}
