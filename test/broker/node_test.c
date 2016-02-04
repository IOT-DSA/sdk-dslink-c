#include "cmocka_init.h"
#include <broker/node.h>
#include <dslink/utils.h>

static
void node_structure_test(void **state) {
    (void) state;

    BrokerNode *root = broker_node_create("", "node");
    assert_non_null(root);
    root->path = dslink_strdup("/");
    {
        assert_non_null(root->path);
        assert_string_equal(root->path, "/");
        assert_string_equal(root->name, "");

        json_t *jis = json_object_get(root->meta, "$is");
        assert_non_null(jis);
        assert_string_equal(json_string_value(jis), "node");
    }

    BrokerNode *a = broker_node_create("a", "node");
    {
        assert_non_null(a);
        assert_true(!broker_node_add(root, a));
        assert_true(dslink_map_contains(root->children, "a"));
        assert_string_equal(a->path, "/a");
    }

    BrokerNode *b = broker_node_create("b", "node");
    {
        assert_non_null(b);
        assert_true(!broker_node_add(a, b));
        assert_true(dslink_map_contains(a->children, "b"));
        assert_string_equal(b->path, "/a/b");
    }

    BrokerNode *c = broker_node_create("c", "node");
    {
        assert_non_null(c);
        assert_true(!broker_node_add(b, c));
        assert_true(dslink_map_contains(b->children, "c"));
        assert_string_equal(c->path, "/a/b/c");
    }

    BrokerNode *d = broker_node_create("d", "node");
    {
        assert_non_null(c);
        assert_true(!broker_node_add(c, d));
        assert_true(dslink_map_contains(c->children, "d"));
        assert_string_equal(d->path, "/a/b/c/d");
    }

    {
        broker_node_free(c);
        assert_false(dslink_map_contains(b->children, "c"));
    }

    broker_node_free(root);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(node_structure_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
