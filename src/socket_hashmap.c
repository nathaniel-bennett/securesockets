#include <stdlib.h>


#include "socket_hashmap.h"


#define MAX_BUCKETS 127

typedef struct node_st node;

struct node_st {
    int id;
    socket_ctx *sock_ctx;
    node *next;
};

/**
 * Hashes the given ID into an index within the hashmap's range.
 * @param id The identifier to hash.
 * @return Some index between 0 and MAX_BUCKETS-1.
 */
int get_index(int id)
{
    return id % MAX_BUCKETS;
}


/* static global hashmap for saving our socket contexts in */
static node *hashmap[MAX_BUCKETS] = {0};


/**
 * Retrieves the socket context with identifier \p id from the internal hashmap.
 * @param id The identifier of the socket context to retrieve.
 * @return A pointer to the socket context, or NULL if no socket context was
 * found with the associated id.
 */
socket_ctx *get_tls_socket(int id)
{
    node *curr = hashmap[get_index(id)];

    while (curr != NULL) {
        if (curr->id == id)
            return curr->sock_ctx;

        curr = curr->next;
    }

    return NULL;
}

/**
 * Adds the given id/sock_ctx pair to the internal socket hashmap.
 * @param id The identifier of the socket to add to the hashmap.
 * @param sock_ctx The socket context associated with \p id.
 * @return 0 if the id/sock_ctx pair were successfully added;
 * 1 if an entry already exists for the given id; and
 * -1 if a new entry could not be allocated.
 */
int add_tls_socket(int id, socket_ctx *sock_ctx)
{
    node *curr;
    node *new_node;

    new_node = malloc(sizeof(node));
    if (new_node == NULL)
        return -1;


    new_node->id = id;
    new_node->sock_ctx = sock_ctx;
    new_node->next = NULL;

    curr = hashmap[get_index(id)];
    if (curr == NULL) {
        hashmap[get_index(id)] = new_node;
        return 0;
    }

    if (curr->id == id) {
        free(new_node);
        return 1;
    }

    while (curr->next != NULL) {
        curr = curr->next;

        if (curr->id == id) {
            free(new_node);
            return 1;
        }
    }

    curr->next = new_node;
    return 0;
}

/**
 * Deletes the entry associated with \p id from the internal socket hashmap.
 * @param id The identifier of the entry to remove.
 * @return 0 if the entry was successfully deleted; or -1 if no entry exists
 * for the given id.
 */
int del_tls_socket(int id)
{
    node *curr;
    node *next;

    curr = hashmap[get_index(id)];
    if (curr == NULL)
        return -1;

    if (curr->id == id) {
        free(curr);
        hashmap[get_index(id)] = NULL;
        return 0;
    }

    while (curr->next != NULL) {
        next = curr->next;
        if (next->id == id) {
            curr->next = next->next;
            free(next);
            return 0;
        }

        curr = curr->next;
    }

    return -1;
}







