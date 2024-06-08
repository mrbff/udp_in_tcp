#include "../includes/udp_in_tcp.h"

int sock = -1;
struct sockaddr_in * g1_addr = NULL;
EVP_PKEY *rsa = NULL;
EVP_PKEY_CTX *pctx = NULL;
unsigned char *pub_key = NULL;
EVP_PKEY_CTX *ctx = NULL;
unsigned char *symmetric_key = NULL;

void clear() {
    if (g1_addr != NULL)
        free(g1_addr);
    if (sock >= 0)
        close(sock);
    if (rsa != NULL)
        EVP_PKEY_free(rsa);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pub_key != NULL)
        OPENSSL_free(pub_key);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (symmetric_key != NULL)
        OPENSSL_free(symmetric_key);
    ERR_free_strings();
    EVP_cleanup();
}

int main() {
    struct sigaction action = { 0 };
    action.sa_handler = &handle_sigint;
    sigaction(SIGINT, &action, &old_action);
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    unsigned char packet[PACKET_MAX_LEN] = "";
    unsigned char encrypted_packet[PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
    unsigned char hmac[HMAC_SIZE] = "";
    unsigned char send_buffer[HMAC_SIZE + IV_SIZE + PACKET_MAX_LEN + AES_BLOCK_SIZE] = "";
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
        clear();
        exit(EXIT_FAILURE);
    }

    if (config.TUNNEL_ON)
        g1_addr = createIPv4Address(config.G1_ip, config.G1_port);
    else
        g1_addr = createIPv4Address(config.C2_ip, config.C2_port);

    if (!g1_addr) {
        perror("address");
        clear();
        exit(EXIT_FAILURE);
    }

    puts("Generating keys...");
    rsa = generate_rsa_key();
    puts("Serializing public key");
    int pub_key_len = i2d_PUBKEY(rsa, &pub_key);
    puts("Sending public key to server");
    if (sendto(sock, pub_key, pub_key_len, 0, (struct sockaddr *)g1_addr, sizeof(struct sockaddr_in)) == -1)
        handle_errors();

    unsigned char encrypted_key[ENCRYPTED_KEY_SIZE];
    puts("Waiting for encryption key...");
    if (recvfrom(sock, encrypted_key, ENCRYPTED_KEY_SIZE, 0, NULL, NULL) == -1)
        handle_errors();
    puts("Received encryption key from server");

    symmetric_key = rsa_decrypt(rsa, encrypted_key, ENCRYPTED_KEY_SIZE);

    puts("Starting sending packets...\n");
    int packet_length = 0;
    int enc_packet_length;
    while (1) {
        generate_random_packet(packet, &packet_length);

        HMAC(EVP_sha256(), symmetric_key, SYMMETRIC_KEY_SIZE, packet, packet_length, hmac, &hmac_len);
        memcpy(send_buffer, hmac, HMAC_SIZE);

        enc_packet_length = encrypt_packet(packet, packet_length, symmetric_key, iv, encrypted_packet);
        memcpy(send_buffer + HMAC_SIZE, iv, IV_SIZE);
        memcpy(send_buffer + HMAC_SIZE + IV_SIZE, encrypted_packet, enc_packet_length);

        if (sendto(sock, send_buffer, HMAC_SIZE + IV_SIZE + enc_packet_length, 0, (struct sockaddr *)g1_addr, sizeof(struct sockaddr_in)) == -1)
            handle_errors();
        printf("Sent packet of length %d\n", packet_length);
        memset(packet, 0, sizeof(packet));
        memset(encrypted_packet, 0, sizeof(encrypted_packet));
        usleep(DELAY);
    }
}