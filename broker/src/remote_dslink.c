#include <string.h>
#include <dslink/utils.h>
#include <dslink/col/map.h>
#include <dslink/err.h>

#include "broker/stream.h"
#include "broker/remote_dslink.h"

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    if (dslink_map_init(&link->local_streams, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal) != 0) {
        return DSLINK_ALLOC_ERR;
    }

    if (dslink_map_init(&link->list_streams, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal) != 0) {
        DSLINK_MAP_FREE(&link->local_streams, {});
        return DSLINK_ALLOC_ERR;
    }

    list_init(&link->onClose.list);

    return 0;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        DSLINK_MAP_FREE(&link->local_streams, {
            free(entry->key);
            broker_stream_free(entry->value);
        });
        DSLINK_MAP_FREE(&link->list_streams, {
            free(entry->key);
        });
        free(link->auth);
    }
    json_decref(link->linkData);
    free(link->ws);
}
