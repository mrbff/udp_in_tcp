#include "../includes/udp_in_tcp.h"

static int sock = -1;
static struct sockaddr_in * g1_addr;

static void handle_client_sigint(int sig) {
    printf("\nGood Bye!\n");
    if (g1_addr != NULL)
        free(g1_addr);
    if (sock >= 0)
        close(sock);
    exit(0);
}

int main() {
    signal(SIGINT, handle_client_sigint);

    unsigned char packet[1024];
    unsigned char key[KEY_SIZE] = "X29aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char hmac[HMAC_SIZE];
    unsigned char send_buffer[1024 + HMAC_SIZE];
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

    if (config.TUNNEL_ON)
        g1_addr = createIPv4Address(config.G1_ip, config.G1_port);
    else
        g1_addr = createIPv4Address(config.C2_ip, config.C2_port);

    while (1) {
        int packet_length = rand() % 1024 + 1;
        generate_random_packet((char *)packet, packet_length);

        HMAC(EVP_sha256(), key, KEY_SIZE, packet, packet_length, hmac, &hmac_len);

        memcpy(send_buffer, hmac, HMAC_SIZE);
        memcpy(send_buffer + HMAC_SIZE, packet, packet_length);

        sendto(sock, send_buffer, HMAC_SIZE + packet_length, 0, (struct sockaddr *)g1_addr, sizeof(struct sockaddr_in));
        printf("Sent packet of length %d\n", packet_length);
        sleep(DELAY);
    }

    close(sock);
    return 0;
}