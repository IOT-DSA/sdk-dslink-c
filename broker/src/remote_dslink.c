#include <string.h>
#include <dslink/utils.h>
#include <broker/stream.h>

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    int ret = 0;
    if (dslink_map_init(&link->responder_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal) != 0) {
        return ret;
    }
    if (dslink_map_init(&link->requester_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal) != 0) {
        dslink_map_free(&link->responder_streams);
        return ret;
    }
    if ((ret = dslink_map_init(&link->sub_sids, dslink_map_uint32_cmp,
                               dslink_map_uint32_key_len_cal)) != 0) {
        dslink_map_free(&link->responder_streams);
        dslink_map_free(&link->requester_streams);
        return ret;
    }
    if ((ret = dslink_map_init(&link->sub_paths, dslink_map_str_cmp,
                               dslink_map_str_key_len_cal)) != 0) {
        dslink_map_free(&link->responder_streams);
        dslink_map_free(&link->requester_streams);
        dslink_map_free(&link->sub_sids);
    }
    return ret;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        dslink_free(link->auth);
    }

    dslink_map_foreach(&link->requester_streams) {
        BrokerStream *stream = entry->value->data;
        requester_stream_closed(stream, *((uint32_t*)entry->key->data));
        broker_stream_free(stream);
        entry->value->data = NULL;
    }
    dslink_map_free(&link->requester_streams);

    dslink_map_foreach(&link->responder_streams) {
        BrokerStream *stream = entry->value->data;
        responder_stream_closed(stream, *((uint32_t*)entry->key->data));
        // free the node only when resp_close_callback return TRUE
        entry->value->data = NULL;
    }
    dslink_map_free(&link->responder_streams);

    dslink_map_free(&link->sub_sids);
    dslink_map_free(&link->sub_paths);
    json_decref(link->linkData);
    wslay_event_context_free(link->ws);
}
