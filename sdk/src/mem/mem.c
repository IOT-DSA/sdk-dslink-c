#include <stdlib.h>
#include "dslink/mem/mem.h"

void *(*dslink_malloc)(size_t) = malloc;
void *(*dslink_calloc)(size_t, size_t) = calloc;
void (*dslink_free)(void *) = free;
