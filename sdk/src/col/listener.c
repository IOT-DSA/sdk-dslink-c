#include <stdlib.h>
#include <string.h>
#include "dslink/col/listener.h"


void add_listener(Dispatcher *dispatcher, int (*callback)(void*, void*), void *data) {
    Listener *listener = malloc(sizeof(Listener));
    listener->callback = callback;
    listener->data = data;
    insert_list_node(&dispatcher->list, listener);
}

void dispatch_message(Dispatcher *dispatcher, void *message) {
    dslink_list_foreach(&dispatcher->list) {
        Listener *listener = (Listener *)node;
        listener->callback(listener->data, message);
    }
}