#include <string.h>
#include <dslink/utils.h>

#include "broker/remote_dslink.h"
#include "broker/stream.h"

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    int rslt = dslink_map_init(&link->responder_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal);
    if (rslt) return rslt;
    rslt = dslink_map_init(&link->requester_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal);
    if (rslt) {
        DSLINK_MAP_FREE(&link->responder_streams,{});
    }
    return rslt;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        free(link->auth);
    }
    DSLINK_MAP_FREE(&link->responder_streams, {
        free(entry->key);
        // TODO: handle value free in a safer way
        //broker_stream_free(entry->value);
    });
    DSLINK_MAP_FREE(&link->requester_streams, {
        free(entry->key);
        // TODO: handle value free in a safer way
        //broker_stream_free(entry->value);
    });
    json_decref(link->linkData);
    wslay_event_context_free(link->ws);
}
