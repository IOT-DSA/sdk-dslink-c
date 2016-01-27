#include <dslink/utils.h>
#include <string.h>
#include <dslink/col/map.h>
#include <dslink/err.h>
#include "broker/remote_dslink.h"

int broker_remote_dslink_init(RemoteDSLink *link) {
    memset(link, 0, sizeof(RemoteDSLink));
    if (dslink_map_init(&link->local_streams, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal) != 0) {
        return DSLINK_ALLOC_ERR;
    }
    return 0;
}

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        free(link->auth);
    }
}
