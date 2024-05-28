#ifndef UDP_IN_TCP_H
#define UDP_IN_TCP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#define SYMMETRIC_KEY_SIZE 32
#define HMAC_SIZE 32  // HMAC-SHA256 output size
#define DELAY 500000 // microseconds
#define PACKET_MAX_LEN 1024
#define CONF_LINE_MAX_LEN  200
#define RSA_KEYGEN_BITS 2048
#define DER_LEN 294
#define ENCRYPTED_KEY_SIZE 256
#define IV_SIZE AES_BLOCK_SIZE

void                    generate_random_packet(unsigned char *packet, int *length);
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
    char C2_ip[16];
    int C2_port;
    char G1_ip[16];
    int G1_port;
    char G2_ip[16];
    int G2_port;
    int TUNNEL_ON;
} t_config;

int     get_config(t_config * config);
void    handle_errors();
void    handle_sigint(int sig);
void    clear();

unsigned char   *generate_symmetric_key();
void            print_hex(unsigned char *data, int len);
EVP_PKEY        *generate_rsa_key();
unsigned char   *rsa_encrypt(EVP_PKEY *pub_key, unsigned char *data, int data_len, int *encrypted_len);
unsigned char   *rsa_decrypt(EVP_PKEY *priv_key, unsigned char *encrypted, int encrypted_len);
void            print_public(EVP_PKEY *pkey);
void            print_private(EVP_PKEY *pkey);

int encrypt_packet(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                   unsigned char *iv, unsigned char *enc_text);
int decrypt_packet(const unsigned char *enc_text, int enc_text_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext);

#endif