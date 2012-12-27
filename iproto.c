#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <libev/ev.h>

static bool initialized = false;
static iproto_stat_t *call_stat = NULL;
static int messages_in_progress = 0;
static struct ev_loop *gloop = NULL;

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
    call_stat = iproto_stat_init("call", NULL);
}

void iproto_free_globals(void) {
    iproto_stat_free(call_stat);
}

static void iproto_call_timeout_cb(EV_P_ ev_timer *w, int revents);
static void iproto_bulk_message_cb(iproto_message_t *message);

static void iproto_send(EV_P_ iproto_message_t *message) {
    iproto_message_ev_t *ev = iproto_message_get_ev(message);
    iproto_message_ev_start(ev, loop);
    iproto_message_ev_dispatch(ev, false);
}

void iproto_bulk(iproto_message_t **messages, int nmessages, struct timeval *timeout) {
    struct timeval begin;
    gettimeofday(&begin, NULL);
    iproto_error_t error = ERR_CODE_OK;

    struct ev_loop *loop = ev_loop_new(0);
    gloop = loop;
    ev_timer *timer = NULL;
    if (timeout) {
        timer = malloc(sizeof(*timer));
        timer->data = &error;
        ev_timer_init(timer, iproto_call_timeout_cb, timeval2ev(*timeout), 0);
        ev_timer_start(loop, timer);
    }

    for (int i = 0; i < nmessages; i++) {
        messages_in_progress++;
        iproto_message_options(messages[i])->callback = iproto_bulk_message_cb;
        iproto_send(loop, messages[i]);
    }

    ev_run(loop, 0);

    if (timer) {
        ev_timer_stop(loop, timer);
        free(timer);
    }
    ev_loop_destroy(loop);
    gloop = NULL;

    assert(messages_in_progress == 0);
    assert(iproto_server_ev_active_count() == 0);

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
    iproto_server_ev_active_done(ERR_CODE_TIMEOUT);
    *(iproto_error_t *)w->data = ERR_CODE_TIMEOUT;
}

static void iproto_bulk_message_cb(iproto_message_t *message) {
    messages_in_progress--;
    if (messages_in_progress == 0)
        ev_break(gloop, EVBREAK_ONE);
}
