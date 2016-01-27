#include <dslink/utils.h>
#include "broker/remote_dslink.h"

void broker_remote_dslink_free(RemoteDSLink *link) {
    if (link->auth) {
        mbedtls_ecdh_free(&link->auth->tempKey);
        DSLINK_CHECKED_EXEC(free, (void *) link->auth->pubKey);
        free(link->auth);
    }
}
