#include "../includes/udp_in_tcp.h"

int udp_sock = -1;
int tcp_sock = -1;
struct sockaddr_in * udp_addr = NULL;
struct sockaddr_in * g2_addr = NULL;

void clear() {
    if (udp_addr != NULL)
        free(udp_addr);
    if (g2_addr != NULL)
        free(g2_addr);
    if (udp_sock >= 0)
        close(udp_sock);
    if (tcp_sock >= 0)
        close(tcp_sock);
}

int main() {
    signal(SIGINT, handle_sigint);

    char buffer[HMAC_SIZE + IV_SIZE + PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
    socklen_t addr_len = sizeof(struct sockaddr_in);
    t_config config;
    int true = 1;

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
    if (!udp_addr) {
        perror("address");
        clear();
        exit(EXIT_FAILURE);
    }
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0) {
        perror("UDP setsockopt");
        clear();
        exit(EXIT_FAILURE);
    }

    if (bind(udp_sock, (struct sockaddr *)udp_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("UDP bind");
        clear();
        exit(EXIT_FAILURE);
    }

    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket");
        clear();
        exit(EXIT_FAILURE);
    }
    if (setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0) {
        perror("TCP setsockopt");
        clear();
        exit(EXIT_FAILURE);
    }

    g2_addr = createIPv4Address(config.G2_ip, config.G2_port);
    if (!g2_addr) {
        perror("address");
        clear();
        exit(EXIT_FAILURE);
    }

    if (connect(tcp_sock, (struct sockaddr *)g2_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("TCP connect");
        clear();
        exit(EXIT_FAILURE);
    }

    int recv_len = recvfrom(udp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)udp_addr, &addr_len);
    if (recv_len > 0) {
        send(tcp_sock, buffer, recv_len, 0);
        puts("Client public key forwarded through tunnel");
    }

    recv(tcp_sock, buffer, sizeof(buffer), 0);
    if (recv_len > 0) {
        sendto(udp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)udp_addr, sizeof(struct sockaddr_in));
        puts("Forwarding encrypted key to client\n");
    }

    while (1) {
        recv_len = recvfrom(udp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)udp_addr, &addr_len);
        if (recv_len > 0) {
            send(tcp_sock, buffer, recv_len, 0);
            printf("Forwarded packet of size %d from UDP to TCP\n", recv_len);
        }
    }
}
