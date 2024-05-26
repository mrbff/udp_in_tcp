#include "../includes/udp_in_tcp.h"

static int udp_sock = -1;
static int tcp_sock = -1;
static struct sockaddr_in * udp_addr;
static struct sockaddr_in * g2_addr;

static void handle_g1_sigint(int sig) {
    printf("\nGood Bye!\n");
    if (udp_addr != NULL)
        free(udp_addr);
    if (g2_addr != NULL)
        free(g2_addr);
    if (udp_sock >= 0)
        close(udp_sock);
    if (tcp_sock >= 0)
        close(tcp_sock);
    exit(0);
}

int main() {
    signal(SIGINT, handle_g1_sigint);

    char buffer[1024 + 32];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    t_config config;

    if (get_config(&config) < 0) {
        perror("config file");
        exit(EXIT_FAILURE);
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket");
        exit(EXIT_FAILURE);
    }

    udp_addr = createIPv4Address("", config.G1_port);

    if (bind(udp_sock, (struct sockaddr *)udp_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("UDP bind");
        close(udp_sock);
        exit(EXIT_FAILURE);
    }

    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket");
        close(udp_sock);
        exit(EXIT_FAILURE);
    }

    g2_addr = createIPv4Address(config.G2_ip, config.G2_port);

    if (connect(tcp_sock, (struct sockaddr *)g2_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("TCP connect");
        close(udp_sock);
        close(tcp_sock);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int recv_len = recvfrom(udp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)udp_addr, &addr_len);
        if (recv_len > 0) {
            send(tcp_sock, buffer, recv_len, 0);
            printf("Forwarded packet of size %d from UDP to TCP\n", recv_len);
        }
    }

    close(udp_sock);
    close(tcp_sock);
    return 0;
}
