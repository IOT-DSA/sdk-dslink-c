#ifndef SDK_DSLINK_C_EVENT_LOOP_H
#define SDK_DSLINK_C_EVENT_LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

struct EventLoop;
struct EventTask;
typedef struct EventLoop EventLoop;
typedef struct EventTask EventTask;

/**
 * \brief            Task function callback that gets executed in the event
 *                   loop.
 * \param loop       The originating event loop that this task was scheduled
 *                   to be executed on.
 * \param nextDelay  Delay of the next task, or 0 if the task shouldn't block.
 */
typedef void (*task_func)(void *funcData,
                          EventLoop *loop);

/**
 * \brief  Called when the event loop wants to block
 *
 * \return How long this function blocked for.
 */
typedef uint32_t (*want_block_func)(void *funcData, EventLoop *loop, uint32_t nextDelay);

struct EventTask {

    uint32_t delay;

    struct EventTask *prev;
    struct EventTask *next;

    task_func func;
    void *func_data;

};

struct EventLoop {
    uint8_t shutdown;
    uint32_t processing_delay;
    want_block_func block_func;
    void *block_func_data;

    EventTask *head;
    EventTask *tail;
};

void dslink_event_loop_init(EventLoop *loop,
                            want_block_func blockFunc,
                            void *blockFuncData);
void dslink_event_loop_free(EventLoop *loop);

int dslink_event_loop_sched(EventLoop *loop, task_func func, void *funcData);
int dslink_event_loop_schedd(EventLoop *loop, task_func func,
                             void *funcData, uint32_t delay);
void dslink_event_loop_process(EventLoop *loop);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_EVENT_LOOP_H
