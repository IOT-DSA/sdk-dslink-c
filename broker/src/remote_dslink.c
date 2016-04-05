#include <string.h>
#include <dslink/utils.h>
#include <broker/permission/permission.h>
#include <broker/msg/msg_subscribe.h>
#include <broker/utils.h>
#include <broker/stream.h>
#include <broker/subscription.h>

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    if (dslink_map_init(&link->responder_streams, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
        || dslink_map_init(&link->requester_streams, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
            ) {
        dslink_map_free(&link->responder_streams);
        dslink_map_free(&link->requester_streams);

        return 1;
    }
    permission_groups_init(&link->permission_groups);
    return 0;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        dslink_free(link->auth);
    }

    link->requester_streams.locked = 1;
    dslink_map_foreach(&link->requester_streams) {
        BrokerStream *stream = entry->value->data;
        requester_stream_closed(stream, link);
        entry->value->data = NULL;
    }

    link->responder_streams.locked = 1;
    dslink_map_foreach(&link->responder_streams) {
        BrokerStream *stream = entry->value->data;
        responder_stream_closed(stream, link);
        // free the node only when resp_close_callback return TRUE
        entry->value->data = NULL;
    }

    List req_sub_to_remove;
    list_init(&req_sub_to_remove);

    if (link->node) {
        dslink_map_foreach(&link->node->req_sub_paths) {
            // find all subscription that doesn't use qos
            SubRequester *subreq = entry->value->data;
            if (subreq->qos == 0) {
                dslink_list_insert(&req_sub_to_remove, subreq);
            }
        }
        dslink_list_foreach(&req_sub_to_remove) {
            // clear non-qos subscription
            SubRequester *subreq = ((ListNode *)node)->value;
            broker_free_sub_requester(subreq);
        }
        dslink_list_free_all_nodes(&req_sub_to_remove);

        dslink_map_foreach(&link->node->req_sub_paths) {
            // find all subscription that doesn't use qos
            SubRequester *subreq = entry->value->data;
            subreq->reqSid = 0xFFFFFFFF;
        }

        dslink_map_clear(&link->node->req_sub_sids);
    }

    dslink_map_free(&link->requester_streams);
    dslink_map_free(&link->responder_streams);

    permission_groups_free(&link->permission_groups);

    if (link->pingTimerHandle) {
        uv_timer_stop(link->pingTimerHandle);
        uv_close((uv_handle_t *) link->pingTimerHandle, broker_free_handle);
    }

    dslink_free((void *) link->path);
    dslink_free(link->lastWriteTime);
    json_decref(link->linkData);

    wslay_event_context_free(link->ws);
    link->ws = NULL;
}
