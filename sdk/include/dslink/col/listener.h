#ifndef SDK_DSLINK_C_LISTENER_H
#define SDK_DSLINK_C_LISTENER_H

#ifdef __cplusplus
extern "C" {
#endif


typedef struct Listener {
    struct Listener *prev;
    struct Listener *next;


    // callback(data, message)
    int (*callback)(void*, void*);
    void *data;
} Listener;

typedef struct Dispatcher {
    // list of Listener
    List list;
} Dispatcher;


void dispatch_message(Dispatcher *dispatcher, void *message);


#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_LISTENER_H
