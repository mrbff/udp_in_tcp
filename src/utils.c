#include "../includes/udp_in_tcp.h"

void generate_random_packet(char *packet, int length) {
    for (int i = 0; i < length; i++) {
        packet[i] = 'A' + (rand() % 26);
    }
}

struct sockaddr_in * createIPv4Address(char * ip, int port) {
    struct sockaddr_in * address;
    address = malloc(sizeof(struct sockaddr_in));
    if (!address) {
        perror("malloc error");
        exit(EXIT_FAILURE);
    }

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (ip == NULL || strlen(ip) == 0)
        address->sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, ip, &address->sin_addr.s_addr) <= 0) {
        perror("inet_pton error");
        free(address);
        exit(EXIT_FAILURE);
    }
    return address;
}

int get_config(t_config * config) {
    FILE *file = fopen("./config/config", "r");
    if (!file) {
        perror("fopen");
        return -1;
    }

    config->TUNNEL_ON = 0;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || !line[0])
            continue ;

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (!strcmp(key, "C1_ip") && value) {
            strncpy(config->C1_ip, value, sizeof(config->C1_ip));
        } else if (!strcmp(key, "C1_port") && value) {
            config->C1_port = atoi(value);
        } else if (!strcmp(key, "C2_ip") && value) {
            strncpy(config->C2_ip, value, sizeof(config->C2_ip));
        } else if (!strcmp(key, "C2_port") && value) {
            config->C2_port = atoi(value);
        } else if (!strcmp(key, "G1_ip") && value) {
            strncpy(config->G1_ip, value, sizeof(config->G1_ip));
        } else if (!strcmp(key, "G1_port") && value) {
            config->G1_port = atoi(value);
        } else if (!strcmp(key, "G2_ip") && value) {
            strncpy(config->G2_ip, value, sizeof(config->G2_ip));
        } else if (!strcmp(key, "G2_port") && value) {
            config->G2_port = atoi(value);
        } else if (!strcmp(key, "TUNNEL_ON")) {
            config->TUNNEL_ON = 1;
        }
    }
    fclose(file);
    return 0;
}