#include "../includes/udp_in_tcp.h"

t_node	*node_create(char *data, int size)
{
    if (size <= 0)
        return (NULL);

    t_node *newNode = malloc(sizeof(t_node));
    if (!newNode) {
        perror("malloc error");
        return (NULL);
    }
    newNode->data = malloc(size);
    if (!newNode->data) {
        perror("malloc error");
        free(newNode);
        return (NULL);
    }

    memcpy(newNode->data, data, size);
    newNode->size = size;
    newNode->next = NULL;
    return (newNode);
}

void insert_ordered(t_node **head, char *data, int size) {
    t_node *newNode = node_create(data, size);
    if (!newNode) {
        perror("packet not stored, malloc error");
        return;
    }

    if (*head == NULL || (*head)->size > size) {
        newNode->next = *head;
        *head = newNode;
    } else {
        t_node *current = *head;
        while (current->next != NULL && current->next->size <= size) {
            current = current->next;
        }
        newNode->next = current->next;
        current->next = newNode;
    }
}

void display_list(t_node *head) {
    t_node *current = head;
    while (current != NULL) {
        printf("Size: %d, Data: %.*s\n", current->size, current->size, current->data);
        current = current->next;
    }
}

void display_list_sizes(t_node *head) {
    t_node *current = head;
    while (current != NULL) {
        printf("%d  ", current->size);
        current = current->next;
    }
    printf("\n");
}

void	clear_list(t_node **head)
{
    t_node	*tmp;

    if (head)
    {
        while (*head)
        {
            tmp = (*head)->next;
            if ((*head)->data)
                free((*head)->data);
            free(*head);
            (*head) = tmp;
        }
        *head = NULL;
    }
}
