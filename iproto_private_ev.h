#ifndef IPROTO_PRIVATE_EV_H_INCLUDED
#define IPROTO_PRIVATE_EV_H_INCLUDED

#include "iproto_private.h"

struct ev_loop;
typedef struct iproto_message_ev iproto_message_ev_t;
typedef struct iproto_server_ev iproto_server_ev_t;

#define timeval2ev(tv) ((tv).tv_sec + (tv).tv_usec / 1000000.)

iproto_message_ev_t *iproto_message_get_ev(iproto_message_t *message);

iproto_server_ev_t *iproto_server_ev_init(iproto_server_t *server);
void iproto_server_ev_free(iproto_server_ev_t *ev);
void iproto_server_ev_start(iproto_server_ev_t *ev, struct ev_loop *loop, struct timeval *connect_timeout);
void iproto_server_ev_connecting(iproto_server_ev_t *ev);
void iproto_server_ev_connected(iproto_server_ev_t *ev);
void iproto_server_ev_update_io(iproto_server_ev_t *ev, int set_events, int unset_events);
void iproto_server_ev_done(iproto_server_ev_t *ev, iproto_error_t error);
void iproto_server_ev_active_done(iproto_error_t error);
int iproto_server_ev_active_count(void);

iproto_message_ev_t *iproto_message_ev_init(iproto_message_t *message);
void iproto_message_ev_free(iproto_message_ev_t *ev);
void iproto_message_ev_start(iproto_message_ev_t *ev, struct ev_loop *loop);
struct ev_loop *iproto_message_ev_loop(iproto_message_ev_t *ev);
void iproto_message_ev_dispatch(iproto_message_ev_t *ev, bool finish);
void iproto_message_ev_start_timer(iproto_message_ev_t *ev);
void iproto_message_ev_stop_timer(iproto_message_ev_t *ev);

#endif
