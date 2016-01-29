#ifndef SDK_DSLINK_C_LISTENER_H
#define SDK_DSLINK_C_LISTENER_H

#ifdef __cplusplus
extern "C" {
#endif


typedef struct Listener {
    struct Listener *prev;
    struct Listener *next;


    // callback(data, parameter)
    int (*callback)(void*, void*);
    void *data;
} Listener;

typedef struct Dispatcher {
    Listener head;
} List;



#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_LISTENER_H
