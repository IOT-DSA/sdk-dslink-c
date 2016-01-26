#include <string.h>
#include <stdlib.h>
#include <mbedtls/timing.h>
#include "dslink/event_loop.h"
#include "dslink/err.h"

static inline
uint8_t is_loop_empty (EventLoop *loop) {
    return loop->head.next == &loop->head;
}

static inline
uint8_t is_loop_not_empty (EventLoop *loop) {
    return loop->head.next != &loop->head;
}

static inline
void insert_after(EventTask *task, EventTask *base) {
    base->next->prev = task;
    task->next = base->next;
    base->next = task;
    task->prev = base;
}

static inline
void insert_before(EventTask * task, EventTask *base) {
    base->prev->next = task;
    task->prev = base->prev;
    base->prev = task;
    task->next = base;
}

static inline
EventTask * remove_task(EventTask *task) {
    task->prev->next = task->next;
    task->next->prev = task->prev;
    return task;
}



static
void dslink_event_loop_sched_raw(EventLoop *loop, EventTask *task) {
    if (is_loop_empty(loop)) {
        insert_after(task, &loop->head);
        return;
    }

    if (task->delay >= loop->head.prev->delay) {
        // Insert at the end of the tail
        insert_before(task, &loop->head);
    } else {
        // Sort the event
        for (EventTask *t = loop->head.prev; t != &loop->head; t = t->prev) {
            if (t->delay <= task->delay) {
                insert_after(task, t);
                break;
            }
        }
    }

    return;
}

static
void dslink_event_loop_sub_del(EventLoop *loop, uint32_t delay) {
    for (EventTask *t = loop->head.next; t != &loop->head; t = t->next) {
        if (t->delay > delay) {
            t->delay -= delay;
        } else {
            t->delay = 0;
        }
    }
}

void dslink_event_loop_init(EventLoop *loop,
                            want_block_func func,
                            void *blockFuncData) {
    memset(loop, 0, sizeof(EventLoop));
    loop->head.next = &loop->head;
    loop->head.prev = &loop->head;
    loop->block_func = func;
    loop->block_func_data = blockFuncData;
}

void dslink_event_loop_free(EventLoop *loop) {
    for (EventTask *t = loop->head.next; t != &loop->head;   ) {
        EventTask *tmp = t->next;
        free(t);
        t = tmp;
    }
}

int dslink_event_loop_sched(EventLoop *loop, task_func func, void *funcData) {
    return dslink_event_loop_schedd(loop, func, funcData, 0);
}

int dslink_event_loop_schedd(EventLoop *loop, task_func func,
                             void *funcData, uint32_t delay) {
    EventTask *task = malloc(sizeof(EventTask));
    if (!task) {
        return DSLINK_ALLOC_ERR;
    }
    task->delay = delay;
    task->func = func;
    task->func_data = funcData;
    dslink_event_loop_sched_raw(loop, task);
    return 0;
}

void dslink_event_loop_process(EventLoop *loop) {
    loop->shutdown = 0;
    while (is_loop_empty(loop) && loop->block_func) {
        loop->block_func(loop->block_func_data, loop, UINT32_MAX);
        if (loop->shutdown) {
            break;
        }
    }
loop_processor:
    while (!loop->shutdown && is_loop_not_empty(loop)) {
        EventTask *task = remove_task(loop->head.next);


        struct mbedtls_timing_hr_time timer;
        while (task->delay > 0) {
            mbedtls_timing_get_timer(&timer, 1);
            loop->block_func(loop->block_func_data,
                             loop, task->delay);
            uint32_t diff = (uint32_t) mbedtls_timing_get_timer(&timer, 0);
            if (task->delay > diff) {
                task->delay -= diff;
            } else {
                task->delay = 0;
            }
            dslink_event_loop_sub_del(loop, diff);
            if (loop->shutdown) {
                free(task);
                goto loop_processor;
            } else if (is_loop_not_empty(loop) && (loop->head.next->delay < task->delay)) {
                dslink_event_loop_sched_raw(loop, task);
                goto loop_processor;
            }
        }

        mbedtls_timing_get_timer(&timer, 1);
        task->func(task->func_data, loop);
        task->delay += (uint32_t) mbedtls_timing_get_timer(&timer, 0);

        // Handle the delays of the next tasks
        dslink_event_loop_sub_del(loop, task->delay);

        free(task);
    }
}
