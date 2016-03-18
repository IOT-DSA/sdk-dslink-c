#include <string.h>
#include <dslink/utils.h>
#include <broker/permission/permission.h>
#include <broker/msg/msg_subscribe.h>
#include "broker/stream.h"

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    if (dslink_map_init(&link->responder_streams, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
        || dslink_map_init(&link->requester_streams, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
        || dslink_map_init(&link->resp_sub_sids, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
       || dslink_map_init(&link->req_sub_sids, dslink_map_uint32_cmp,
                          dslink_map_uint32_key_len_cal, dslink_map_hash_key) != 0
        || dslink_map_init(&link->sub_paths, dslink_map_str_cmp,
                           dslink_map_str_key_len_cal, dslink_map_hash_key) != 0
        || dslink_map_init(&link->local_subs, dslink_map_str_cmp,
                           dslink_map_str_key_len_cal, dslink_map_hash_key) != 0) {
        dslink_map_free(&link->responder_streams);
        dslink_map_free(&link->requester_streams);
        dslink_map_free(&link->resp_sub_sids);
        dslink_map_free(&link->req_sub_sids);
        dslink_map_free(&link->sub_paths);
        dslink_map_free(&link->local_subs);
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

    dslink_map_foreach(&link->local_subs) {
        Listener *l = entry->value->data;
        listener_remove(l);
        dslink_free(l->data);
        dslink_free(l);
    }

    dslink_map_foreach(&link->resp_sub_sids) {
        BrokerSubStream *stream = entry->value->data;
        dslink_map_foreach(&stream->clients) {
            RemoteDSLink *l = entry->key->data;
            uint32_t *sid = entry->value->data;
            broker_subscribe_disconnected_remote(l,
                                                 stream->remote_path->data,
                                                 *sid);
        }
        stream->responder = NULL;
    }

    dslink_map_foreach(&link->req_sub_sids) {
        BrokerSubStream *stream = entry->value->data;
        broker_stream_free((BrokerStream *) stream, link);
    }

    dslink_map_free(&link->local_subs);
    dslink_map_free(&link->sub_paths);
    dslink_map_free(&link->resp_sub_sids);
    dslink_map_free(&link->req_sub_sids);

    dslink_map_free(&link->requester_streams);
    dslink_map_free(&link->responder_streams);

    permission_groups_free(&link->permission_groups);
    dslink_free((void *) link->path);
    json_decref(link->linkData);
    wslay_event_context_free(link->ws);
    link->ws = NULL;
}
