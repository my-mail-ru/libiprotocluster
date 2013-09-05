#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <libev/ev.h>
#include "khash.h"

KHASH_INIT(server_ev_set, iproto_server_ev_t *, char, 0, kh_req_hash_func, kh_req_hash_equal);

typedef struct {
    int messages_in_progress;
    khash_t(server_ev_set) *active_servers;
} iproto_ev_loop_data_t;

static bool initialized = false;
static struct ev_loop *iproto_loop = NULL;
static iproto_stat_t *call_stat = NULL;

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

void iproto_init_globals(void) {
    iproto_loop = ev_loop_new(0);
    iproto_ev_loop_data_t *loop_data = malloc(sizeof(*loop_data));
    loop_data->messages_in_progress = 0;
    loop_data->active_servers = kh_init(server_ev_set, NULL, realloc);
    ev_set_userdata(iproto_loop, loop_data);
    ev_suspend(iproto_loop);
    call_stat = iproto_stat_init("call", NULL);
}

void iproto_free_globals(void) {
    ev_resume(iproto_loop);
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(iproto_loop);
    kh_destroy(server_ev_set, loop_data->active_servers);
    free(loop_data);
    ev_loop_destroy(iproto_loop);
    iproto_stat_free(call_stat);
}

static void iproto_call_timeout_cb(EV_P_ ev_timer *w, int revents);
static void iproto_bulk_message_cb(iproto_message_t *message);

static bool iproto_send(EV_P_ iproto_message_t *message) {
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

    struct ev_loop *loop = iproto_loop;
    ev_resume(loop);
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(iproto_loop);

    ev_timer *timer = NULL;
    if (timeout) {
        timer = malloc(sizeof(*timer));
        timer->data = &error;
        ev_timer_init(timer, iproto_call_timeout_cb, timeval2ev(*timeout), 0);
        ev_timer_start(loop, timer);
    }

    for (int i = 0; i < nmessages; i++) {
        iproto_message_options(messages[i])->callback = iproto_bulk_message_cb;
        if (iproto_send(loop, messages[i]))
            loop_data->messages_in_progress++;
    }

    if (loop_data->messages_in_progress != 0)
        ev_run(loop, 0);

    assert(loop_data->messages_in_progress == 0);
    assert(kh_size(loop_data->active_servers) == 0);

    if (timer) {
        ev_timer_stop(loop, timer);
        free(timer);
    }
    ev_suspend(loop);

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

static void iproto_call_timeout_cb(EV_P_ ev_timer *w, int revents) {
    iproto_log(LOG_ERROR | LOG_EV, "call timeout");
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(loop);
    khiter_t k;
    foreach (loop_data->active_servers, k) {
        iproto_server_ev_t *ev = kh_key(loop_data->active_servers, k);
        iproto_server_ev_cancel(ev, ERR_CODE_TIMEOUT);
    }
    kh_clear(server_ev_set, loop_data->active_servers);
    *(iproto_error_t *)w->data = ERR_CODE_TIMEOUT;
}

static void iproto_bulk_message_cb(iproto_message_t *message) {
    iproto_message_ev_t *ev = iproto_message_get_ev(message);
    struct ev_loop *loop = iproto_message_ev_loop(ev);
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(loop);
    if (--loop_data->messages_in_progress == 0)
        ev_break(loop, EVBREAK_ONE);
}

void iproto_ev_loop_add_server(struct ev_loop *loop, iproto_server_ev_t *ev) {
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(loop);
    int ret;
    kh_put(server_ev_set, loop_data->active_servers, ev, &ret);
}

void iproto_ev_loop_remove_server(struct ev_loop *loop, iproto_server_ev_t *ev) {
    iproto_ev_loop_data_t *loop_data = (iproto_ev_loop_data_t *)ev_userdata(loop);
    khiter_t k = kh_get(server_ev_set, loop_data->active_servers, ev);
    kh_del(server_ev_set, loop_data->active_servers, k);
}
