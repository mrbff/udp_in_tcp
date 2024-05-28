#include "../includes/udp_in_tcp.h"

void generate_random_packet(unsigned char *packet, int *length) {
    if (RAND_bytes((unsigned char*)length, sizeof(int)) != 1) handle_errors();
    (*length) = (abs(*length) % PACKET_MAX_LEN) + 1;
    if (RAND_bytes(packet, *length) != 1) handle_errors();
}

struct sockaddr_in * createIPv4Address(char * ip, int port) {
    if (port < 0) {
        perror("invalid port");
        return (NULL);
    }

    struct sockaddr_in * address;
    address = malloc(sizeof(struct sockaddr_in));
    if (!address) {
        perror("malloc error");
        return (NULL);
    }

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (ip == NULL || strlen(ip) == 0)
        address->sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, ip, &address->sin_addr.s_addr) <= 0) {
        perror("inet_pton error");
        free(address);
        return (NULL);
    }
    return (address);
}

int get_config(t_config * config) {
    if (!config)
        return (-1);
    FILE *file = fopen("./config/config.cfg", "r");
    if (!file) {
        perror("fopen");
        return (-1);
    }

    config->TUNNEL_ON = 0;
    char line[CONF_LINE_MAX_LEN];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || !line[0])
            continue ;

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");

        if (!strcmp(key, "C2_ip") && value) {
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
        } else if (!strcmp(key, "TUNNEL_ON") || !strcmp(key, "TUNNEL_ON\n")) {
            config->TUNNEL_ON = 1;
        }
    }
    fclose(file);
    return (0);
}

void handle_sigint(int sig) {
    printf("\nGood Bye!\n");
    (void)sig;
    clear();
    exit(0);
}

void handle_errors() {
    ERR_print_errors_fp(stderr);
    clear();
    abort();
}

unsigned char *generate_symmetric_key() {
    unsigned char *key = malloc(SYMMETRIC_KEY_SIZE);
    if (!key) handle_errors();

    if (!RAND_bytes(key, SYMMETRIC_KEY_SIZE)) {
        OPENSSL_free(key);
        handle_errors();
    }
    return key;
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

EVP_PKEY *generate_rsa_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!pctx) handle_errors();
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, RSA_KEYGEN_BITS) <= 0) handle_errors();
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handle_errors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

unsigned char *rsa_encrypt(EVP_PKEY *pub_key, unsigned char *data, int data_len, int *encrypted_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) handle_errors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handle_errors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data, data_len) <= 0) handle_errors();

    unsigned char *encrypted = OPENSSL_malloc(outlen);
    if (!encrypted) handle_errors();

    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, data, data_len) <= 0) handle_errors();

    *encrypted_len = outlen;
    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}

unsigned char *rsa_decrypt(EVP_PKEY *priv_key, unsigned char *encrypted, int encrypted_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) handle_errors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handle_errors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, encrypted_len) <= 0) handle_errors();

    unsigned char *decrypted = malloc(outlen);
    if (!decrypted) handle_errors();

    if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, encrypted_len) <= 0) handle_errors();

    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

void print_public(EVP_PKEY *pkey)
{
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(bp, pkey, 1, NULL);
    BIO_free(bp);
}

void print_private(EVP_PKEY *pkey) {
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(bp, pkey, 1, NULL);
    BIO_free(bp);
}

int encrypt_packet(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                   unsigned char *iv, unsigned char *enc_text) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int enc_text_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();
    if( EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) handle_errors();

    if (RAND_bytes(iv, IV_SIZE) != 1) handle_errors();

    if(EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1) handle_errors();

    if(EVP_EncryptUpdate(ctx, enc_text, &len, plaintext, plaintext_len) != 1) handle_errors();
    enc_text_len = len;

    if(EVP_EncryptFinal_ex(ctx, enc_text + len, &len) != 1) handle_errors();
    enc_text_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return (enc_text_len);
}

int decrypt_packet(const unsigned char *enc_text, int enc_text_len, const unsigned char *key,
                   const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_errors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, enc_text, enc_text_len)) handle_errors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_errors();;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return (plaintext_len);
}