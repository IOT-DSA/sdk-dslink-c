#ifndef SDK_DSLINK_C_LISTENER_H
#define SDK_DSLINK_C_LISTENER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"

typedef struct Listener {
    struct Listener *prev;
    struct Listener *next;
    List * list;

    // callback(data, message)
    int (*callback)(void*, void*);
    void *data;
} Listener;

typedef struct Dispatcher {
    // list of Listener
    List list;
} Dispatcher;


void add_listener(Dispatcher *dispatcher, int (*callback)(void*, void*), void *data);

void dispatch_message(Dispatcher *dispatcher, void *message);

// dispatch message and remove all listeners
void dispatch_and_remove_all(Dispatcher *dispatcher, void *message);

#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_LISTENER_H
