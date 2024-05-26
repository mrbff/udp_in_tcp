#ifndef UDP_IN_TCP_H
#define UDP_IN_TCP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <signal.h>

#define KEY_SIZE 32  // HMAC key size
#define HMAC_SIZE 32  // HMAC-SHA256 output size
#define DELAY 2 // in seconds

void                    generate_random_packet(char *packet, int length);
struct sockaddr_in *    createIPv4Address(char * ip, int port);

typedef struct s_node {
    char            *data;
    int             size;
    struct s_node   *next;
} t_node;

void    insert_ordered(t_node **head, char *data, int size);
t_node  *node_create(char *data, int size);
void    display_list(t_node *head);
void    display_list_sizes(t_node *head);
void	clear_list(t_node **head);

typedef struct s_config {
    char C1_ip[16];
    int C1_port;
    char C2_ip[16];
    int C2_port;
    char G1_ip[16];
    int G1_port;
    char G2_ip[16];
    int G2_port;
    int TUNNEL_ON;
} t_config;

int get_config(t_config * config);

#endif