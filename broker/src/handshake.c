#include <string.h>


#define LOG_TAG "handshake"
#include <dslink/log.h>

#include <dslink/handshake.h>
#include <dslink/utils.h>
#include <dslink/base64_url.h>
#include <dslink/crypto.h>

#include "broker/config.h"
#include "broker/sys/token.h"
#include "broker/net/ws_handler.h"
#include "broker/net/ws.h"
#include "broker/utils.h"
#include "broker/msg/msg_list.h"
#include "broker/handshake.h"

#include <wslay_event.h>
#include <sys/time.h>

static
int generate_salt(unsigned char *salt, size_t len) {
    unsigned char buf[32];

    dslink_crypto_random(buf, sizeof(buf));

    if (dslink_base64_encode(salt,
                              len, &len,
                              buf, sizeof(buf)) != 0) {
        return -1;
    }

    return 0;
}

json_t *broker_handshake_handle_conn(Broker *broker,
                                     const char *dsId,
                                     const char *token,
                                     json_t *handshake) {
    if (dslink_map_contains(&broker->client_connecting, (void *) dsId)) {
        ref_t *ref = dslink_map_remove_get(&broker->client_connecting,
                                           (void *) dsId);
        RemoteDSLink *link = ref->data;
        dslink_map_remove(&broker->client_connecting,
                          (void *) link->name);
        broker_remote_dslink_free(link);
        dslink_free(link);
        dslink_decref(ref);
    }

    RemoteDSLink *link = dslink_calloc(1, sizeof(RemoteDSLink));
    json_t *resp = json_object();
    if (!(link && resp)) {
        goto fail;
    }

    if (broker_remote_dslink_init(link) != 0) {
        goto fail;
    }

    link->broker = broker;
    link->auth = dslink_malloc(sizeof(RemoteAuth));
    if (!link->auth) {
        goto fail;
    }

    dslink_crypto_ecdh_init_context(&link->auth->tempKey);

    if (dslink_handshake_generate_key_pair(&link->auth->tempKey) != 0) {
        log_err("Failed to create temporary key for DSLink\n");
        goto fail;
    }

    {
        json_t *jsonPubKey = json_object_get(handshake, "publicKey");
        if (!jsonPubKey) {
            goto fail;
        }

        const char *tmp = json_string_value(jsonPubKey);
        if (!tmp) {
            goto fail;
        }
        tmp = dslink_strdup(tmp);
        if (!tmp) {
            goto fail;
        }
        link->auth->pubKey = tmp;
    }

    char tempKey[90];
    size_t tempKeyLen = 0;
    if (dslink_handshake_encode_pub_key(&link->auth->tempKey, tempKey,
                                        sizeof(tempKey), &tempKeyLen) != 0) {
        goto fail;
    }

    if (generate_salt((unsigned char *) link->auth->salt,
                      sizeof(link->auth->salt)) != 0) {
        goto fail;
    }

    json_object_set_new_nocheck(resp, "wsUri", json_string_nocheck("/ws"));
    json_object_set_new_nocheck(resp, "tempKey", json_string_nocheck(tempKey));
    json_object_set_new_nocheck(resp, "salt", json_string_nocheck(link->auth->salt));
    if (json_boolean_value(json_object_get(handshake, "isResponder"))) {
        link->isResponder = 1;
    }

    if (json_boolean_value(json_object_get(handshake, "isRequester"))) {
        link->isRequester = 1;
    }

    json_t *linkData = json_object_get(handshake, "linkData");
    if (json_is_object(linkData)) {
        json_incref(linkData);
        link->linkData = linkData;
    }

    {
        char buf[512] = {0};
        snprintf(buf, sizeof(buf), "/downstream/");
        char *name = buf + sizeof("/downstream/")-1;

        size_t dsIdLen = strlen(dsId);
        if (dsIdLen < 44) {
            goto fail;
        }
        size_t nameLen = dsIdLen - 43;
        if (dsId[nameLen - 1] == '-') {
            nameLen--;
        }
        int nodeExists = 0;
        // find a valid name from broker->client_names
        memcpy(name, dsId, nameLen);
        while (1) {
            ref_t *ref = dslink_map_get(&broker->client_connecting, name);
            if (ref) {
                RemoteDSLink *l = ref->data;
                if (l && l->dsId && strcmp(l->dsId->data, dsId) == 0) {
                    dslink_map_remove(&broker->client_connecting, name);
                    broker_remote_dslink_free(l);
                    break;
                } else {
                    name[nameLen] = dsId[nameLen];
                    nameLen++;
                }
            }
            ref = dslink_map_get(broker->downstream->children,
                                 (void *) name);
            if (ref == NULL) {
                break;
            }

            if (!((DownstreamNode *) ref->data)->dsId || strcmp(dsId, ((DownstreamNode *) ref->data)->dsId->data) == 0) {
                nodeExists = 1;
                break;
            }

            name[nameLen] = dsId[nameLen];
            nameLen++;
        }

        ref_t *downstreamNodeRef = dslink_map_get(broker->downstream->children, name);
        DownstreamNode *downstreamNodeNow = downstreamNodeRef ? downstreamNodeRef->data : NULL;

        if (broker_enable_token && !nodeExists) {
            BrokerNode* tokenNode = NULL;
            if (!token) {
                log_err("Failed to connect, you need a token.\n");
                goto fail;
            } else {
                tokenNode = get_token_node(token, dsId);
            }

            if (tokenNode) {
                DownstreamNode *node = nodeExists == 1 ? downstreamNodeNow : broker_init_downstream_node(broker->downstream, name);

                if (node) {
                    json_object_set_new_nocheck(node->meta, "$$token", json_string_nocheck(tokenNode->name));

                    node->dsId = dslink_str_ref(dsId);
                    if (broker->downstream->list_stream) {
                        node->link = link;
                        update_list_child(broker->downstream,
                                          broker->downstream->list_stream,
                                          name);
                        node->link = NULL;
                    }

                    json_t *group = json_object_get(tokenNode->meta, "$$group");
                    if (json_is_string(group)) {
                        json_object_set_nocheck(node->meta, "$$group", group);
                    }

                    token_used(tokenNode);

                    broker_downstream_nodes_changed(broker);
                } else {
                    log_err("No node found");
                    goto fail;
                }
            } else {
                log_err("Invalid token: %s\n", token);
                goto fail;
            }
        }
        json_object_set_new_nocheck(resp, "path", json_string_nocheck(buf));

        // FORMATS
        link->is_msgpack = 0;
        json_t* formats_from_link = json_object_get(handshake, "formats");

        if(formats_from_link != NULL && json_array_size(formats_from_link) > 0)
        {
            // According to docs, link orders its communication type with most prefered ones comes first
            int arr_size = json_array_size(formats_from_link);
            for(int i = 0; i < arr_size; i++)
            {
                const char* preference = json_string_value(json_array_get(formats_from_link, i));

                if(!preference) continue;

                if(strcmp("json", preference) == 0) {
                    link->is_msgpack = 0; break;
                }
                else if(strcmp("msgpack", preference) == 0) {
                    link->is_msgpack = 1; break;
                }
            }
        }

        json_object_set_new_nocheck(resp, "format", json_string_nocheck(
                link->is_msgpack == 1?"msgpack":"json"));

        link->path = dslink_strdup(buf);
        if (!link->path) {
            goto fail;
        }
        link->name = link->path + sizeof("/downstream/") - 1;

        // add to connecting map with the name
        if (dslink_map_set(&broker->client_connecting,
                           dslink_ref((void *) link->name, NULL),
                           dslink_ref(link, NULL)) != 0) {
            dslink_free((void *) link->path);
            goto fail;
        }
    }

    {
        ref_t *tmp = dslink_ref(dslink_strdup(dsId), dslink_free);
        if (!tmp) {
            goto fail;
        }
        // add to connecting map with dsId
        if (dslink_map_set(&broker->client_connecting, tmp,
                           dslink_ref(link, NULL)) != 0) {
            dslink_free(tmp);
            goto fail;
        }
    }

    return resp;
fail:
    if (link) {
        broker_remote_dslink_free(link);
        dslink_free((void *) link->path);
        dslink_free(link);
    }
    DSLINK_CHECKED_EXEC(json_decref, resp);
    return NULL;
}

int dslink_generic_ping_handler(RemoteDSLink *link) {
    if(!link)
        return 0;

    if (link->lastWriteTime) {
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        long time_diff = current_time.tv_sec - link->lastWriteTime->tv_sec;
        if (time_diff >= 30) {
            broker_ws_send_ping(link);
        }
    } else {
        broker_ws_send_ping(link);
    }

    if (link->lastReceiveTime) {
        struct timeval current_time;
        gettimeofday(&current_time, NULL);
        long time_diff = current_time.tv_sec - link->lastReceiveTime->tv_sec;
        if (time_diff >= 60) {
            if(link->pendingClose == 0)
                link->pendingClose = 1;
            return 0;
        }
    }
    return 1;
}

void dslink_handle_ping(uv_timer_t* handle) {
    RemoteDSLink *link = handle->data;

    if(!dslink_generic_ping_handler(link)) {
        log_debug("Remote dslink problem while pinging!\n");
        broker_close_link(link);
    }
}

int broker_handshake_handle_ws(Broker *broker,
                               Client *client,
                               const char *dsId,
                               const char *auth,
                               const char *wsAccept) {

    ref_t *oldDsId = NULL;
    ref_t *ref = dslink_map_remove_get(&broker->client_connecting,
                                       (char *) dsId);
    if (!ref) {
        return 1;
    }
    RemoteDSLink *link = ref->data;
    dslink_decref(ref);
    if (link->name) {
        dslink_map_remove(&broker->client_connecting,
                          (char *) link->name);
    }
    if (!(auth && link->auth->pubKey)) {
        return 1;
    }

#ifndef BROKER_PING_THREAD
    uv_timer_t *ping_timer = NULL;
#endif
    int ret = 0;
    { // Perform auth check
        char expectedAuth[90];
        if (dslink_handshake_gen_auth_key(&link->auth->tempKey,
                                          link->auth->pubKey,
                                          link->auth->salt,
                                          (unsigned char *) expectedAuth,
                                          sizeof(expectedAuth)) != 0) {
            ret = 1;
            goto exit;
        }

        if (strcmp(expectedAuth, auth) != 0) {
            ret = 1;
            goto exit;
        }
    }

    DownstreamNode *node = NULL;
    int pendingUpdateList = 0;
    { // Handle retrieval of the downstream node
        ref = dslink_map_get(broker->downstream->children,
                                    (char *) link->name);
        if (!ref) {
            node = broker_init_downstream_node(broker->downstream, link->name);
            if (!node) {
                ret = 1;
                goto exit;
            }
            oldDsId = dslink_ref(dslink_strdup(dsId), dslink_free);
            if (broker->downstream->list_stream) {
                pendingUpdateList = 1;
            }
            broker_downstream_nodes_changed(broker);
        } else {
            node = ref->data;
            oldDsId = node->dsId;
        }
    }

    if (node->link) {
//        Client *c = node->link->client;
        broker_close_link(node->link);
//        uv_poll_t *poll = c->poll;
//        dslink_socket_free(c->sock);
//        dslink_free(c);
//        uv_close((uv_handle_t *) poll, broker_free_handle);
    }
    
    // add permission group to link
    if (node->groups) {
        permission_groups_load(&link->permission_groups, dsId, json_string_value(node->groups));
    } else {
        permission_groups_load(&link->permission_groups, dsId, NULL);
    }


    link->client = client;
    link->dsId = oldDsId;
    link->node = node;
    node->dsId = dslink_incref(oldDsId);
    client->sock_data = link;

    json_object_set_new_nocheck(node->meta, "$$dsId", json_string_nocheck(dsId));

    wslay_event_context_ptr ws;
    if (wslay_event_context_server_init(&ws,
                                        broker_ws_callbacks(),
                                        link) != 0) {
        ret = 1;
        goto exit;
    }
    link->ws = ws;
    broker_ws_send_init(client->sock, wsAccept);



#ifndef BROKER_PING_THREAD
    ping_timer = dslink_malloc(sizeof(uv_timer_t));
    ping_timer->data = link;
    uv_timer_init(link->client->poll->loop, ping_timer);
    uv_timer_start(ping_timer, dslink_handle_ping, 1000, 10000);
    link->pingTimerHandle = ping_timer;
#endif

    // set the ->link and update all existing stream
    broker_dslink_connect(node, link);

    if (pendingUpdateList) {
        update_list_child(broker->downstream,
                          broker->downstream->list_stream,
                          link->name);
    }

    ref_t *tmp = dslink_ref(dslink_strdup(dsId), dslink_free);
    if (!tmp) {
        ret = 1;
        goto exit;
    }
    // add to connected map with the dsid
    if (dslink_map_set(&broker->remote_connected, tmp,
                       dslink_ref(link, NULL)) != 0) {
        log_warn("DSLink %s couldn't be added to list\n",link->name);
        dslink_free(tmp);
        ret = 1;
        goto exit;
    }

    log_info("DSLink `%s` has connected\n", dsId);

exit:
    dslink_crypto_ecdh_deinit_context(&link->auth->tempKey);
    dslink_free((void *) link->auth->pubKey);
    dslink_free(link->auth);
    link->auth = NULL;
    if (ret != 0) {
        dslink_map_free(&link->requester_streams);
        dslink_map_free(&link->responder_streams);
        dslink_free((char *)link->path);
        dslink_free(link);


#ifndef BROKER_PING_THREAD
        if (ping_timer) {
            uv_timer_stop(ping_timer);
            uv_close((uv_handle_t *) ping_timer, broker_free_handle);
        }
#endif
    }

    return ret;
}

int broker_local_handle_ws(Broker *broker,
                           Client *client,
                           const char *wsAccept,
                           const char* perm_group,
                           const char* session,
                           const char* format) {
#ifndef BROKER_PING_THREAD
    uv_timer_t *ping_timer = NULL;
#endif
    RemoteDSLink *link = dslink_calloc(1, sizeof(RemoteDSLink));
    if (!link) {
        goto fail;
    }

    if (broker_remote_dslink_init(link) != 0) {
        goto fail;
    }

    link->broker = broker;
    link->isResponder = 0;
    link->isRequester = 1;

    //FORMAT
    link->is_msgpack = 0;
    if(strcmp(format,"msgpack") == 0)
        link->is_msgpack = 1;


    char buf[512] = {0};
    snprintf(buf, sizeof(buf), "/dglux-%s",session);
    link->dsId = dslink_ref(dslink_strdup(buf+1), dslink_free);
    link->name = (char*)link->dsId->data;//dslink_strdup("dglux");
    link->path = dslink_strdup(buf);


    // add permission group to link
    permission_groups_load(&link->permission_groups, (const char*)link->dsId->data, perm_group);

    link->client = client;
    client->sock_data = link;


    wslay_event_context_ptr ws;
    if (wslay_event_context_server_init(&ws,
                                        broker_ws_callbacks(),
                                        link) != 0) {
        goto fail;
    }
    link->ws = ws;
    broker_ws_send_init(client->sock, wsAccept);

#ifndef BROKER_PING_THREAD
    ping_timer = dslink_malloc(sizeof(uv_timer_t));
    ping_timer->data = link;
    uv_timer_init(link->client->poll->loop, ping_timer);
    uv_timer_start(ping_timer, dslink_handle_ping, 1000, 10000);
    link->pingTimerHandle = ping_timer;
#endif

    update_list_child(broker->downstream,
                      broker->downstream->list_stream,
                      link->name);

    ref_t *tmp = dslink_ref(dslink_strdup(buf+1), dslink_free);
    if (!tmp) {
        goto fail;
    }
    // add to connected map with the dsid
    if (dslink_map_set(&broker->remote_connected,tmp,
                       dslink_ref(link, NULL)) != 0) {
        log_warn("DSLink %s couldn't be added to list\n",link->name);
        dslink_free(tmp);
        goto fail;
    }

    log_info("Local DSLink has connected!\n");

    return 0;

fail:
    if (link) {
        dslink_map_free(&link->requester_streams);
        dslink_map_free(&link->responder_streams);
        broker_remote_dslink_free(link);
        if(link->path)
            dslink_free((void *) link->path);
        dslink_free(link);
    }
#ifndef BROKER_PING_THREAD
    if (ping_timer) {
        uv_timer_stop(ping_timer);
        uv_close((uv_handle_t *) ping_timer, broker_free_handle);
    }
#endif
    return 1;
}
