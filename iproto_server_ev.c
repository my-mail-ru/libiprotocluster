#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <libev/ev.h>
#include "khash.h"

struct iproto_server_ev {
    iproto_server_t *server;
    struct ev_loop *loop;
    ev_io *io;
    ev_timer *connect_timeout;
    iproto_stat_t *poll_stat;
    struct timeval start_time;
};

KHASH_INIT(server_ev_set, iproto_server_ev_t *, char, 0, kh_req_hash_func, kh_req_hash_equal);
static khash_t(server_ev_set) *active_servers = NULL;

static void iproto_server_ev_io_cb(EV_P_ ev_io *w, int revents);
static void iproto_server_ev_connect_timeout_cb(EV_P_ ev_timer *w, int revents);

iproto_server_ev_t *iproto_server_ev_init(iproto_server_t *server) {
    iproto_server_ev_t *ev = malloc(sizeof(*ev));
    ev->io = malloc(sizeof(*ev->io));
    ev->connect_timeout = malloc(sizeof(*ev->connect_timeout));
    ev->io->data = ev;
    ev->connect_timeout->data = ev;
    ev->server = server;
    ev->loop = NULL;
    ev->poll_stat = iproto_stat_init("poll", iproto_server_hostport(server));
    ev_init(ev->connect_timeout, iproto_server_ev_connect_timeout_cb);
    ev_init(ev->io, iproto_server_ev_io_cb);
    return ev;
}

void iproto_server_ev_free(iproto_server_ev_t *ev) {
    if (ev->loop) {
        ev_timer_stop(ev->loop, ev->connect_timeout);
        ev_io_stop(ev->loop, ev->io);
    }
    iproto_stat_free(ev->poll_stat);
    free(ev->connect_timeout);
    free(ev->io);
    free(ev);
}

void iproto_server_ev_start(iproto_server_ev_t *ev, struct ev_loop *loop, struct timeval *connect_timeout) {
    assert(ev->loop == NULL);
    gettimeofday(&ev->start_time, NULL);
    ev->loop = loop;
    ev_timer_set(ev->connect_timeout, timeval2ev(*connect_timeout), 0);
    int ret;
    if (active_servers == NULL)
        active_servers = kh_init(server_ev_set, NULL, realloc);
    kh_put(server_ev_set, active_servers, ev, &ret);
    ev_io_set(ev->io, iproto_server_get_fd(ev->server), EV_WRITE);
    ev_io_start(ev->loop, ev->io);
}

void iproto_server_ev_done(iproto_server_ev_t *ev, iproto_error_t error) {
    khiter_t k = kh_get(server_ev_set, active_servers, ev);
    kh_del(server_ev_set, active_servers, k);
    ev_timer_stop(ev->loop, ev->connect_timeout);
    ev_io_stop(ev->loop, ev->io);
    ev->loop = NULL;
    iproto_stat_insert(ev->poll_stat, error, &ev->start_time);
}

void iproto_server_ev_connecting(iproto_server_ev_t *ev) {
    ev_timer_start(ev->loop, ev->connect_timeout);
}

void iproto_server_ev_connected(iproto_server_ev_t *ev) {
    ev_timer_stop(ev->loop, ev->connect_timeout);
}

void iproto_server_ev_update_io(iproto_server_ev_t *ev, int set_events, int unset_events) {
    int events = (ev->io->events | set_events) & ~unset_events;
    if (events == 0) {
        iproto_log(LOG_DEBUG | LOG_EV, "server %s: all events done", iproto_server_hostport(ev->server));
        iproto_server_ev_done(ev, ERR_CODE_OK);
    } else if (events != ev->io->events) {
        iproto_log(LOG_DEBUG | LOG_EV, "server %s: wait for events 0x%x", iproto_server_hostport(ev->server), events);
        ev_io_stop(ev->loop, ev->io);
        ev_io_set(ev->io, ev->io->fd, events);
        ev_io_start(ev->loop, ev->io);
    }
}

static void iproto_server_ev_post_handle(iproto_server_ev_t *ev, bool finish) {
    iproto_message_t *message;
    while ((message = iproto_server_recv(ev->server))) {
        iproto_message_ev_dispatch(iproto_message_get_ev(message), finish);
    }
}

static void iproto_server_ev_io_cb(EV_P_ ev_io *w, int revents) {
    iproto_server_ev_t *ev = (iproto_server_ev_t *)w->data;
    iproto_server_t *server = ev->server;
    iproto_server_handle_io(server, revents);
    iproto_server_ev_post_handle(ev, false);
}

static void iproto_server_ev_connect_timeout_cb(EV_P_ ev_timer *w, int revents) {
    iproto_server_ev_t *ev = (iproto_server_ev_t *)w->data;
    iproto_server_t *server = ev->server;
    iproto_log(LOG_ERROR | LOG_EV, "server %s: connect timeout", iproto_server_hostport(server));
    ev_timer_stop(EV_A_ w);
    ev_io_stop(EV_A_ ev->io);
    iproto_server_handle_error(server, ERR_CODE_TIMEOUT);
    iproto_server_ev_post_handle(ev, false);
}

void iproto_server_ev_active_done(iproto_error_t error) {
    khiter_t k;
    foreach (active_servers, k) {
        iproto_server_ev_t *ev = kh_key(active_servers, k);
        iproto_server_handle_error(ev->server, error);
        iproto_server_ev_post_handle(ev, true);
    }
    kh_clear(server_ev_set, active_servers);
}

int iproto_server_ev_active_count(void) {
    return kh_size(active_servers);
}
