#ifndef IPROTO_PRIVATE_EV_H_INCLUDED
#define IPROTO_PRIVATE_EV_H_INCLUDED

#include "iproto_private.h"
#include "iproto_evapi.h"

enum {
    EV_READ  = 0x01, /* ev_io detected read will not block */
    EV_WRITE = 0x02  /* ev_io detected write will not block */
};

enum {
    EVRUN_NOWAIT = 1, /* do not block/wait */
    EVRUN_ONCE   = 2  /* block *once* only */
};

enum {
    EVBREAK_CANCEL = 0, /* undo unloop */
    EVBREAK_ONE    = 1, /* unloop once */
    EVBREAK_ALL    = 2  /* unloop all loops */
};

extern iproto_evapi_t iproto_evapi;
# define EV_DEFAULT                iproto_evapi.loop
# define ev_loop_fork(loop)        iproto_evapi.loop_fork ((loop))
# define ev_now_update(loop)       iproto_evapi.now_update ((loop))
# define ev_run(l,flags)           iproto_evapi.run ((l), (flags))
# define ev_break(loop, how)       iproto_evapi.break_ ((loop), (how))
# define ev_suspend(loop)          iproto_evapi.suspend ((loop))
# define ev_resume(loop)           iproto_evapi.resume ((loop))
# define ev_io_new(c)              iproto_evapi.io_new ((c))
# define ev_io_free(w)             iproto_evapi.io_free (w)
# define ev_io_set(w,f,e)          iproto_evapi.io_set ((w), (f), (e))
# define ev_io_get(w,f,e)          iproto_evapi.io_get ((w), (f), (e))
# define ev_io_set_data(w,d)       iproto_evapi.io_set_data ((w), (d))
# define ev_io_data(w)             iproto_evapi.io_data ((w))
# define ev_io_start(l,w)          iproto_evapi.io_start ((l), (w))
# define ev_io_stop(l,w)           iproto_evapi.io_stop  ((l), (w))
# define ev_timer_new(c)           iproto_evapi.timer_new ((c))
# define ev_timer_free(w)          iproto_evapi.timer_free (w)
# define ev_timer_set(w,a,r)       iproto_evapi.timer_set ((w), (a), (r))
# define ev_timer_set_data(w,d)    iproto_evapi.timer_set_data ((w), (d))
# define ev_timer_data(w)          iproto_evapi.timer_data ((w))
# define ev_timer_start(l,w)       iproto_evapi.timer_start ((l), (w))
# define ev_timer_stop(l,w)        iproto_evapi.timer_stop  ((l), (w))
# define ev_timer_again(l,w)       iproto_evapi.timer_again  ((l), (w))
void iproto_evapi_initialize(void);

typedef struct iproto_message_ev iproto_message_ev_t;
typedef struct iproto_server_ev iproto_server_ev_t;

#define timeval2ev(tv) ((tv).tv_sec + (tv).tv_usec / 1000000.)

iproto_server_ev_t *iproto_server_get_ev(iproto_server_t *server);
iproto_message_ev_t *iproto_message_get_ev(iproto_message_t *message);

iproto_server_ev_t *iproto_server_ev_init(iproto_server_t *server);
void iproto_server_ev_free(iproto_server_ev_t *ev);
void iproto_server_ev_start(iproto_server_ev_t *ev, struct ev_loop *loop, struct timeval *connect_timeout);
void iproto_server_ev_connecting(iproto_server_ev_t *ev);
void iproto_server_ev_connected(iproto_server_ev_t *ev);
void iproto_server_ev_update_io(iproto_server_ev_t *ev, int set_events, int unset_events);
void iproto_server_ev_done(iproto_server_ev_t *ev, iproto_error_t error);
void iproto_server_ev_cancel(iproto_server_ev_t *ev, iproto_error_t error);

iproto_message_ev_t *iproto_message_ev_init(iproto_message_t *message);
void iproto_message_ev_free(iproto_message_ev_t *ev);
void iproto_message_ev_start(iproto_message_ev_t *ev, struct ev_loop *loop);
struct ev_loop *iproto_message_ev_loop(iproto_message_ev_t *ev);
void iproto_message_ev_dispatch(iproto_message_ev_t *ev, bool finish);
void iproto_message_ev_start_timer(iproto_message_ev_t *ev);
void iproto_message_ev_stop_timer(iproto_message_ev_t *ev);
void iproto_message_ev_set_data(iproto_message_ev_t *ev, void *data);
void *iproto_message_ev_data(iproto_message_ev_t *ev);

#endif
