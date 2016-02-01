#include <string.h>
#include <dslink/utils.h>
#include "broker/remote_dslink.h"

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    int ret = 0;
    if (dslink_map_init(&link->responder_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal) != 0) {
        return ret;
    }
    if (dslink_map_init(&link->requester_streams, dslink_map_uint32_cmp,
                           dslink_map_uint32_key_len_cal) != 0) {
        DSLINK_MAP_FREE(&link->responder_streams, {});
        return ret;
    }
    if ((ret = dslink_map_init(&link->sub_sids, dslink_map_uint32_cmp,
                               dslink_map_uint32_key_len_cal)) != 0) {
        DSLINK_MAP_FREE(&link->responder_streams, {});
        DSLINK_MAP_FREE(&link->requester_streams, {});
        return ret;
    }
    if ((ret = dslink_map_init(&link->sub_paths, dslink_map_str_cmp,
                               dslink_map_str_key_len_cal)) != 0) {
        DSLINK_MAP_FREE(&link->responder_streams, {});
        DSLINK_MAP_FREE(&link->requester_streams, {});
        DSLINK_MAP_FREE(&link->sub_sids, {});
    }
    return ret;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        dslink_free(link->auth);
    }
    DSLINK_MAP_FREE(&link->responder_streams, {
        dslink_free(entry->key);
        // TODO: handle value free in a safer way
        //broker_stream_free(entry->value);
    });
    DSLINK_MAP_FREE(&link->requester_streams, {
        dslink_free(entry->key);
        // TODO: handle value free in a safer way
        //broker_stream_free(entry->value);
    });
    DSLINK_MAP_FREE(&link->sub_sids, {
        dslink_free(entry->key);
        // TODO: free value
    });
    DSLINK_MAP_FREE(&link->sub_paths, {
        dslink_free(entry->key);
        // TODO: free value
    });
    json_decref(link->linkData);
    wslay_event_context_free(link->ws);
}
