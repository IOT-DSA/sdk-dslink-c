#include <broker/node.h>

void virtual_downstream_node_init(VirtualDownstreamNode *node) {
    node->permissionList = NULL;
    dslink_map_init(&node->childrenNode, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);
    node->meta = json_object();
}

void virtual_downstream_node_free(VirtualDownstreamNode *pnode) {
    json_decref(pnode->meta);
    virtual_downstream_free_map(&pnode->childrenNode);
    permission_list_free(pnode->permissionList);
    dslink_free(pnode);
}

void virtual_downstream_free_map(Map *map) {
    dslink_map_foreach(map) {
        VirtualDownstreamNode* node = entry->value->data;
        virtual_downstream_node_free(node);
    }
    dslink_map_free(map);
}
