#include "../includes/udp_in_tcp.h"

int sock = -1;
t_node *head = NULL;
struct sockaddr_in * server_addr = NULL;
unsigned char * symmetric_key = NULL;
unsigned char *encrypted_key = NULL;
EVP_PKEY *client_pkey = NULL;

void clear() {
    if (server_addr != NULL)
        free(server_addr);
    clear_list(&head);
    if (sock >= 0)
        close(sock);
    if (symmetric_key != NULL)
        OPENSSL_free(symmetric_key);
    if (encrypted_key != NULL)
        OPENSSL_free(encrypted_key);
    if (client_pkey != NULL)
        EVP_PKEY_free(client_pkey);
    ERR_free_strings();
    EVP_cleanup();
}

int main() {
    signal(SIGINT, handle_sigint);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    struct sockaddr_in client_addr;
    unsigned char buffer[ HMAC_SIZE + IV_SIZE + PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
    unsigned char packet[PACKET_MAX_LEN] = "";
    unsigned char encrypted_packet[PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
    unsigned char received_hmac[HMAC_SIZE] = "";
    unsigned char calculated_hmac[HMAC_SIZE] = "";
    socklen_t addr_len = sizeof(client_addr);
    unsigned int hmac_len;
    t_config config;
    int true = 1;
    unsigned char iv[IV_SIZE] = "";

    if (get_config(&config) < 0) {
        perror("config file");
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0) {
        perror("setsockopt");
        close(sock);
        exit(EXIT_FAILURE);
    }

    server_addr = createIPv4Address("", config.C2_port);
    if (!server_addr) {
        perror("address");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("bind");
        close(sock);
        free(server_addr);
        exit(EXIT_FAILURE);
    }

    symmetric_key = generate_symmetric_key();
    puts("Symmetric key generated");
    unsigned char client_pub_key[DER_LEN];
    puts("Waiting for client public key");
    int client_pub_key_len = recvfrom(sock, client_pub_key, sizeof(client_pub_key), 0, (struct sockaddr *)&client_addr, &addr_len);
    puts("Public key received from client");
    const unsigned char *p = client_pub_key;
    puts("Deserializing client public key");
    client_pkey = d2i_PUBKEY(NULL, &p, client_pub_key_len);
    if (!client_pkey) handle_errors();

    int encrypted_len;
    encrypted_key = rsa_encrypt(client_pkey, symmetric_key, SYMMETRIC_KEY_SIZE, &encrypted_len);
    puts("Symmetric key encrypted");

    puts("Sending encrypted key to client");
    sendto(sock, encrypted_key, encrypted_len, 0, (struct sockaddr *)&client_addr, addr_len);
    OPENSSL_free(encrypted_key);
    encrypted_key = NULL;
    EVP_PKEY_free(client_pkey);
    client_pkey = NULL;

    puts("Waiting to receive packets...\n\n");
    int packet_length = 0;
    int enc_packet_length = 0;
    while (1) {
        int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (recv_len > 0) {
            memcpy(received_hmac, buffer, HMAC_SIZE);
            memcpy(iv, buffer + HMAC_SIZE, IV_SIZE);
            enc_packet_length = recv_len - HMAC_SIZE - IV_SIZE;
            memcpy(encrypted_packet, buffer + HMAC_SIZE + IV_SIZE, enc_packet_length);

            packet_length = decrypt_packet(encrypted_packet, enc_packet_length, symmetric_key, iv, packet);
            HMAC(EVP_sha256(), symmetric_key, SYMMETRIC_KEY_SIZE, packet, packet_length, calculated_hmac, &hmac_len);

            if (CRYPTO_memcmp(received_hmac, calculated_hmac, HMAC_SIZE) == 0) {
                printf("Received packet of size %d with valid authentication\n", packet_length);
                insert_ordered(&head, (char *)packet, packet_length);
                display_list_sizes(head);
                printf("\n");
            } else {
                printf("Received packet with invalid HMAC. Dropping packet.\n");
            }
        }
        memset(packet, 0, sizeof(packet));
        memset(encrypted_packet, 0, sizeof(encrypted_packet));
    }
}