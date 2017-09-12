#ifndef BROKER_EXTENSION_H
#define BROKER_EXTENSION_H

#include <broker/node.h>


#ifdef __cplusplus
extern "C" {
#endif

    struct ExtensionConfig {
        char* brokerUrl;
        uv_loop_t* loop;
    };

    typedef void (*extension_link_connect_callback)(DownstreamNode* node);
    typedef void (*extension_link_disconnect_callback)(DownstreamNode* node);

    struct ExtensionCallbacks
    {
        extension_link_connect_callback connect_callback;
        extension_link_disconnect_callback disconnect_callback;
    };

    typedef int (*init_ds_extension_type)(BrokerNode* sysNode, const struct ExtensionConfig* config, struct ExtensionCallbacks* callbacks);
    typedef int (*deinit_ds_extension_type)();

#ifdef __cplusplus
}
#endif

#endif // BROKER_EXTENSION_H
