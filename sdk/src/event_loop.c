#include <string.h>
#include <stdlib.h>
#include <mbedtls/timing.h>
#include "dslink/mem/mem.h"
#include "dslink/col/list.h"
#include "dslink/event_loop.h"
#include "dslink/err.h"

static
void dslink_event_loop_sched_raw(EventLoop *loop, EventTask *task) {
    if (list_is_empty(&loop->list)) {
        list_insert_node(&loop->list, task);
        return;
    }

    if (task->delay >= ((EventTask *) loop->list.head.prev)->delay) {
        // Insert at the end of the tail
        list_insert_node_before(task, &loop->list.head);
    } else {
        // Sort the event
        for (EventTask *t = (EventTask *)loop->list.head.prev; (void*)t != &loop->list.head; t = t->prev) {
            if (t->delay <= task->delay) {
                list_insert_node_after(task, t);
                break;
            }
        }
    }

    return;
}

static
void dslink_event_loop_sub_del(EventLoop *loop, uint32_t delay) {
    for (EventTask *t = (EventTask *)loop->list.head.next; (void *)t != &loop->list.head; t = t->next) {
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
    loop->list.head.next = &loop->list.head;
    loop->list.head.prev = &loop->list.head;
    loop->block_func = func;
    loop->block_func_data = blockFuncData;
}

void dslink_event_loop_free(EventLoop *loop) {
    for (EventTask *t = (EventTask *)loop->list.head.next; (void *)t != &loop->list.head;) {
        EventTask *tmp = t->next;
        dslink_free(t);
        t = tmp;
    }
}

int dslink_event_loop_sched(EventLoop *loop, task_func func, void *funcData) {
    return dslink_event_loop_schedd(loop, func, funcData, 0);
}

int dslink_event_loop_schedd(EventLoop *loop, task_func func,
                             void *funcData, uint32_t delay) {
    EventTask *task = dslink_malloc(sizeof(EventTask));
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
    while (list_is_empty(&loop->list) && loop->block_func) {
        loop->block_func(loop->block_func_data, loop, UINT32_MAX);
        if (loop->shutdown) {
            break;
        }
    }
    loop_processor:
    while (!loop->shutdown && list_is_not_empty(&loop->list)) {
        EventTask *task = list_remove_node(loop->list.head.next);


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
                dslink_free(task);
                goto loop_processor;
            } else if (list_is_not_empty(&loop->list) && ((EventTask *)loop->list.head.next)->delay < task->delay) {
                dslink_event_loop_sched_raw(loop, task);
                goto loop_processor;
            }
        }

        mbedtls_timing_get_timer(&timer, 1);
        task->func(task->func_data, loop);
        task->delay += (uint32_t) mbedtls_timing_get_timer(&timer, 0);

        // Handle the delays of the next tasks
        dslink_event_loop_sub_del(loop, task->delay);

        dslink_free(task);
    }
}
