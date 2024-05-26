#include "../includes/udp_in_tcp.h"

static int tcp_sock = -1;
static int new_sock = -1;
static int udp_sock = -1;
static struct sockaddr_in * g2_addr;
static struct sockaddr_in * c2_addr;

static void handle_g2_sigint(int sig) {
    printf("\nGood Bye!\n");
    if (g2_addr != NULL)
        free(g2_addr);
    if (c2_addr != NULL)
        free(c2_addr);
    if (udp_sock >= 0)
        close(udp_sock);
    if (tcp_sock >= 0)
        close(tcp_sock);
    if (new_sock >= 0)
        close(new_sock);
    exit(0);
}

int main() {
    signal(SIGINT, handle_g2_sigint);

    char buffer[1024 + 32];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    t_config config;

    if (get_config(&config) < 0) {
        perror("config file");
        exit(EXIT_FAILURE);
    }

    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket");
        exit(EXIT_FAILURE);
    }

    g2_addr = createIPv4Address("", config.G2_port);

    if (bind(tcp_sock, (struct sockaddr *)g2_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("TCP bind");
        close(tcp_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(tcp_sock, 5) < 0) {
        perror("TCP listen");
        close(tcp_sock);
        exit(EXIT_FAILURE);
    }

    new_sock = accept(tcp_sock, (struct sockaddr *)g2_addr, &addr_len);
    if (new_sock < 0) {
        perror("TCP accept");
        close(tcp_sock);
        exit(EXIT_FAILURE);
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket");
        close(tcp_sock);
        close(new_sock);
        exit(EXIT_FAILURE);
    }

    c2_addr = createIPv4Address(config.C2_ip, config.C2_port);

    while (1) {
        int recv_len = recv(new_sock, buffer, sizeof(buffer), 0);
        if (recv_len > 0) {
            sendto(udp_sock, buffer, recv_len, 0, (struct sockaddr *)c2_addr, sizeof(struct sockaddr_in));
            printf("Forwarded packet of size %d from TCP to UDP\n", recv_len);
        }
    }

    close(tcp_sock);
    close(new_sock);
    close(udp_sock);
    return 0;
}