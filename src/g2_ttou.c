#include "../includes/udp_in_tcp.h"

int tcp_sock = -1;
int new_sock = -1;
int udp_sock = -1;
struct sockaddr_in * g2_addr = NULL;
struct sockaddr_in * c2_addr = NULL;

void clear() {
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
}

int main() {
    struct sigaction action = { 0 };
    action.sa_handler = &handle_sigint;
    sigaction(SIGINT, &action, &old_action);

    char buffer[HMAC_SIZE + IV_SIZE + PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
    socklen_t addr_len = sizeof(struct sockaddr_in);
    t_config config;
    int true = 1;

    if (get_config(&config) < 0) {
        perror("config file");
        exit(EXIT_FAILURE);
    }

    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0) {
        perror("TCP setsockopt");
        clear();
        exit(EXIT_FAILURE);
    }

    g2_addr = createIPv4Address("", config.G2_port);
    if (!g2_addr) {
        perror("address");
        clear();
        exit(EXIT_FAILURE);
    }

    if (bind(tcp_sock, (struct sockaddr *)g2_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("TCP bind");
        clear();
        exit(EXIT_FAILURE);
    }

    if (listen(tcp_sock, 5) < 0) {
        perror("TCP listen");
        clear();
        exit(EXIT_FAILURE);
    }

    new_sock = accept(tcp_sock, (struct sockaddr *)g2_addr, &addr_len);
    if (new_sock < 0) {
        perror("TCP accept");
        clear();
        exit(EXIT_FAILURE);
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket");
        clear();
        exit(EXIT_FAILURE);
    }
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0) {
        perror("UDP setsockopt");
        clear();
        exit(EXIT_FAILURE);
    }

    c2_addr = createIPv4Address(config.C2_ip, config.C2_port);
    if (!c2_addr) {
        perror("address");
        clear();
        exit(EXIT_FAILURE);
    }

    int recv_len = recv(new_sock, buffer, sizeof(buffer), 0);
    if (recv_len > 0) {
        sendto(udp_sock, buffer, recv_len, 0, (struct sockaddr *)c2_addr, sizeof(struct sockaddr_in));
        puts("Client public key forwarded to server");
    }

    recv_len = recvfrom(udp_sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (recv_len > 0) {
        send(new_sock, buffer, sizeof(buffer), 0);
        puts("Forwarding encrypted key from server through tunnel\n");
    }

    while (1) {
        recv_len = recv(new_sock, buffer, sizeof(buffer), 0);
        if (recv_len > 0) {
            sendto(udp_sock, buffer, recv_len, 0, (struct sockaddr *)c2_addr, sizeof(struct sockaddr_in));
            printf("Forwarded packet of size %d from TCP to UDP\n", recv_len);
        }
    }
}