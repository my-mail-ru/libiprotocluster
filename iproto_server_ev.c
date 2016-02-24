#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <stdlib.h>
#include <sys/time.h>

struct iproto_server_ev {
    iproto_server_t *server;
    struct ev_loop *loop;
    ev_io *io;
    ev_timer *connect_timeout;
    struct timeval start_time;
};

static void iproto_server_ev_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void iproto_server_ev_connect_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);

iproto_server_ev_t *iproto_server_ev_init(iproto_server_t *server) {
    iproto_server_ev_t *ev = malloc(sizeof(*ev));
    ev->io = ev_io_new(iproto_server_ev_io_cb);
    ev->connect_timeout = ev_timer_new(iproto_server_ev_connect_timeout_cb);
    ev_timer_set_priority(ev->connect_timeout, IPROTO_TIMEOUTPRI);
    ev_io_set_data(ev->io, ev);
    ev_timer_set_data(ev->connect_timeout, ev);
    ev->server = server;
    ev->loop = EV_DEFAULT;
    return ev;
}

void iproto_server_ev_free(iproto_server_ev_t *ev) {
    ev_timer_free(ev->connect_timeout);
    ev_io_free(ev->io);
    free(ev);
}

void iproto_server_ev_set_connect_timeout(iproto_server_ev_t *ev, struct timeval *connect_timeout) {
    ev_timer_set(ev->connect_timeout, timeval2ev(*connect_timeout), 0);
}

void iproto_server_ev_connect(iproto_server_ev_t *ev, int fd) {
    ev_io_set(ev->io, fd, EV_WRITE);
    ev_io_start(ev->loop, ev->io);
    ev_timer_start(ev->loop, ev->connect_timeout);
}

void iproto_server_ev_connected(iproto_server_ev_t *ev) {
    ev_timer_stop(ev->loop, ev->connect_timeout);
}

void iproto_server_ev_close(iproto_server_ev_t *ev) {
    ev_timer_stop(ev->loop, ev->connect_timeout);
    ev_io_stop(ev->loop, ev->io);
}

void iproto_server_ev_update_io(iproto_server_ev_t *ev, int set_events, int unset_events) {
    int events, fd;
    ev_io_get(ev->io, &fd, &events);
    int new_events = (events | set_events) & ~unset_events;
    if (new_events != events) {
        ev_io_stop(ev->loop, ev->io);
        ev_io_set(ev->io, fd, new_events);
        if (new_events != 0) {
            ev_io_start(ev->loop, ev->io);
            iproto_log(LOG_DEBUG | LOG_EV, "server %s: wait for events 0x%x", iproto_server_hostport(ev->server), new_events);
        } else {
            iproto_log(LOG_DEBUG | LOG_EV, "server %s: all events done", iproto_server_hostport(ev->server));
        }
    }
}

static void iproto_server_ev_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    iproto_server_ev_t *ev = (iproto_server_ev_t *)ev_io_data(w);
    iproto_server_t *server = ev->server;
    iproto_server_handle_io(server, revents);
    iproto_server_recv_and_dispatch(server, false);
}

static void iproto_server_ev_connect_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_server_ev_t *ev = (iproto_server_ev_t *)ev_timer_data(w);
    iproto_server_t *server = ev->server;
    iproto_log(LOG_ERROR | LOG_EV, "server %s: connect timeout", iproto_server_hostport(server));
    ev_timer_stop(loop, w);
    ev_io_stop(loop, ev->io);
    iproto_server_handle_error(server, ERR_CODE_TIMEOUT);
    iproto_server_recv_and_dispatch(server, false);
}
