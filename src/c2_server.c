#include "../includes/udp_in_tcp.h"

static int sock = -1;
static t_node *head = NULL;
static struct sockaddr_in * server_addr;

static void handle_server_sigint(int sign) {
    printf("\nGood Bye!\n");
    if (server_addr != NULL)
        free(server_addr);
    clear_list(&head);
    if (sock >= 0)
        close(sock);
    exit(0);
}

int main() {
    signal(SIGINT, handle_server_sigint);

    struct sockaddr_in client_addr;
    unsigned char key[KEY_SIZE] = "X29aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char buffer[1024 + HMAC_SIZE];
    unsigned char packet[1024];
    unsigned char received_hmac[HMAC_SIZE];
    unsigned char calculated_hmac[HMAC_SIZE];
    socklen_t addr_len = sizeof(client_addr);
    unsigned int hmac_len;
    t_config config;

    if (get_config(&config) < 0) {
        perror("config file");
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    server_addr = createIPv4Address("", config.C2_port);

    if (bind(sock, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (recv_len > 0) {
            memcpy(received_hmac, buffer, HMAC_SIZE);
            int packet_length = recv_len - HMAC_SIZE;
            memcpy(packet, buffer + HMAC_SIZE, packet_length);

            HMAC(EVP_sha256(), key, KEY_SIZE, packet, packet_length, calculated_hmac, &hmac_len);

            if (CRYPTO_memcmp(received_hmac, calculated_hmac, HMAC_SIZE) == 0) {
                printf("Received packet of size %d with valid authentication\n", packet_length);
                insert_ordered(&head, (char *)packet, packet_length);
                display_list_sizes(head);
                printf("\n\n");
            } else {
                printf("Received packet with invalid HMAC. Dropping packet.\n");
            }
        }
    }

    close(sock);
    return 0;
}