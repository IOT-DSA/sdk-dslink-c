#include <string.h>

#include "broker/config.h"
#include "broker/broker.h"

#define LOG_TAG "broker"
#include <dslink/log.h>
#include <dslink/utils.h>

int data_node_populate(BrokerNode *data_node) {
  int ret = 0;

  if (!data_node) {
      ret = 1;
      goto exit;
  }

  {
      BrokerNode *node = broker_node_create("addNode", "node");
      if (!node) {
          ret = 1;
          goto exit;
      }

      if (broker_node_add(data_node, node) != 0) {
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      char *invokable = dslink_strdup("$invokable");
      char *write = dslink_strdup("$write");

      dslink_map_set(node->meta, invokable, (void **) &write);

      char *params = dslink_strdup("$params");
      json_t *param_list = json_array();

      if (!param_list) {
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      json_t *name = json_object();

      if (!name) {
        json_delete(param_list);
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      json_object_set_new_nocheck(name, "name", json_string("Name"));
      json_object_set_new_nocheck(name, "type", json_string("string"));

      json_array_append_new(param_list, name);

      dslink_map_set(node->meta, params, (void **) &param_list);
  }

  {
      BrokerNode *node = broker_node_create("addValue", "node");
      if (!node) {
          ret = 1;
          goto exit;
      }

      if (broker_node_add(data_node, node) != 0) {
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      char *invokable = dslink_strdup("$invokable");
      char *write = dslink_strdup("$write");

      dslink_map_set(node->meta, invokable, (void **) &write);

      char *params = dslink_strdup("$params");
      json_t *param_list = json_array();

      if (!param_list) {
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      dslink_map_set(node->meta, params, (void **) &param_list);

      json_t *name = json_object();

      if (!name) {
          json_delete(param_list);
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      json_object_set_new_nocheck(name, "name", json_string("Name"));
      json_object_set_new_nocheck(name, "type", json_string("string"));

      json_array_append_new(param_list, name);

      json_t *type = json_object();

      if (!type) {
          json_delete(param_list);
          json_delete(name);
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      json_object_set_new_nocheck(type, "name", json_string("Type"));
      json_object_set_new_nocheck(type, "type", json_string("enum[string,number,bool,array,map,dynamic]"));

      json_array_append_new(param_list, type);

      json_t *editor = json_object();

      if (!editor) {
          json_delete(param_list);
          json_delete(name);
          json_delete(type);
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      json_object_set_new_nocheck(editor, "name", json_string("Editor"));
      json_object_set_new_nocheck(editor, "type", json_string("enum[none,textarea,password,daterange,date]"));

      json_array_append_new(param_list, editor);
  }

  {
      BrokerNode *node = broker_node_create("publish", "node");
      if (!node) {
          ret = 1;
          goto exit;
      }

      if (broker_node_add(data_node, node) != 0) {
          broker_node_free(node);
          ret = 1;
          goto exit;
      }

      char *invokable = dslink_strdup("$invokable");
      char *write = dslink_strdup("$write");

      dslink_map_set(node->meta, invokable, (void **) &write);

      char *params = dslink_strdup("$params");
      json_t *param_list = json_array();

      if (!param_list) {
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      dslink_map_set(node->meta, params, (void **) &param_list);

      json_t *path = json_object();

      if (!path) {
        json_delete(param_list);
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      json_object_set_new_nocheck(path, "name", json_string("Path"));
      json_object_set_new_nocheck(path, "type", json_string("string"));

      json_array_append_new(param_list, path);

      json_t *value = json_object();

      if (!value) {
        json_delete(param_list);
        json_delete(path);
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      json_object_set_new_nocheck(value, "name", json_string("Value"));
      json_object_set_new_nocheck(value, "type", json_string("dynamic"));

      json_array_append_new(param_list, value);

      json_t *timestamp = json_object();

      if (!timestamp) {
        json_delete(param_list);
        json_delete(path);
        json_delete(value);
        broker_node_free(node);
        ret = 1;
        goto exit;
      }

      json_object_set_new_nocheck(timestamp, "name", json_string("Timestamp"));
      json_object_set_new_nocheck(timestamp, "type", json_string("string"));

      json_array_append_new(param_list, timestamp);
  }
exit:
    return ret;
}

int data_node_add() {
  int ret = 0;
  return ret;
}
