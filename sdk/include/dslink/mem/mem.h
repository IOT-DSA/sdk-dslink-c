#ifndef SDK_DSLINK_C_MEM_H
#define SDK_DSLINK_C_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

extern void *(*dslink_calloc)(size_t, size_t);
extern void *(*dslink_malloc)(size_t);
extern void *(*dslink_realloc)(void *ptr, size_t);
extern void (*dslink_free)(void *);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_MEM_H
