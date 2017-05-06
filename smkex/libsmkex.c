#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "crypto.h"
#include "pkt.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

#define SMKEX_MAX_FD    1024

int select_subflow(int oldflags, int index) {
    int newflags = oldflags;
    unsigned char* p = (unsigned char*)&newflags;
    p[2] |= index;
    return newflags;
}

struct mp_socket_s {
    int used;
    unsigned char* session_key;
    unsigned char* iv;

    unsigned char* recv_buffer;
    unsigned char* recv_buffer_cursor;
    smkex_pkt* recv_stored_ppkt;
    size_t recv_remaining;

    struct {
        unsigned char* local_nonce;
        unsigned char* remote_nonce;
        unsigned char* local_pub_key;
        unsigned int local_pub_key_length;
        unsigned char* remote_pub_key;
        unsigned int remote_pub_key_length;
    } session;
} mp_sockets[SMKEX_MAX_FD];

int initialized = 0;

void __initialize(void) {
    if (initialized == 0) {
        SSL_load_error_strings();
        initialized = 1;
    }
}


EC_KEY* __new_key_pair(void) {
    // Initialize new curve
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not create EC key.\n");
        return NULL;
    }

    // Generate local key pair
    int rc = EC_KEY_generate_key(ec_key);
    if (rc == 0) {
        fprintf(stderr, "Error: Could not generate ECDH key.\n");
        return NULL;
    }

    return ec_key;
}


int __send_local_key(int sockfd, EC_KEY* key) {
    ssize_t (*original_send)(int, const void*, size_t, int) = dlsym(RTLD_NEXT, "send");

    const EC_GROUP* ec_group = EC_KEY_get0_group(key);
    const EC_POINT* ec_pub_key = EC_KEY_get0_public_key(key);

    // Compute size of public key byte representation
    size_t pub_key_size = EC_POINT_point2oct(ec_group, ec_pub_key,
            POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (pub_key_size == 0) {
        fprintf(stderr, "Error: Could not compute ECDH exchange length.\n");
        return -1;
    }

    // Allocate space for byte representation
    mp_sockets[sockfd].session.local_pub_key_length = pub_key_size;
    mp_sockets[sockfd].session.local_pub_key = malloc(pub_key_size);
    if (mp_sockets[sockfd].session.local_pub_key == NULL) {
        fprintf(stderr, "Error: could not allocate memory for local public key.\n");
        return -1;
    }

    // Generate random nonce for exchange
    mp_sockets[sockfd].session.local_nonce = malloc(SESSION_NONCE_LENGTH);
    if (mp_sockets[sockfd].session.local_nonce == NULL) {
        fprintf(stderr, "Error: could not allocate memory for nonce.\n");
        return -1;
    }
    if (!RAND_bytes(mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH)) {
        fprintf(stderr, "Error: could not generate nonce.\n");
        return -1;
    }

    // Convert to bytes
    int rc = EC_POINT_point2oct(ec_group, ec_pub_key, POINT_CONVERSION_UNCOMPRESSED,
            mp_sockets[sockfd].session.local_pub_key, pub_key_size, NULL);
    if (rc == 0) {
         fprintf(stderr, "Error: Could not convert ECDH exchange to bytestring.\n");
         return -1;
    }

    // Prepare message
    smkex_pkt* ppkt = smkex_pkt_allocate(SESSION_NONCE_LENGTH + pub_key_size);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for server pkt.\n");
        return -1;
    }

    memcpy(ppkt->value, mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH);
    memcpy(ppkt->value + SESSION_NONCE_LENGTH, mp_sockets[sockfd].session.local_pub_key,
            pub_key_size);

    ppkt->type = TLV_TYPE_DH;
    ppkt->length = pub_key_size + SESSION_NONCE_LENGTH;
    ppkt->send = original_send;

    // Public keys are always sent on the master subflow
    rc = smkex_pkt_send(ppkt, sockfd, select_subflow(0, 1));
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send our public key.\n");
        return -1;
    }

    return 0;
}


/*
 * Format is:
 * [ local_nonce | local_pub_key | remote_nonce | remote_pub_key ]
 */
int __send_session_info(int sockfd) {
    ssize_t (*original_send)(int, const void*, size_t, int) = dlsym(RTLD_NEXT, "send");

    // Build session info string
    size_t session_length = 2 * SESSION_NONCE_LENGTH +
            mp_sockets[sockfd].session.local_pub_key_length +
            mp_sockets[sockfd].session.remote_pub_key_length;

    unsigned char* session = malloc(session_length);
    if (session == NULL) {
        fprintf(stderr, "Error: could not allocate session memory.\n");
        return -1;
    }

    unsigned char* cursor = session;
    memcpy(cursor, mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH);
    cursor += SESSION_NONCE_LENGTH;

    memcpy(cursor, mp_sockets[sockfd].session.local_pub_key,
            mp_sockets[sockfd].session.local_pub_key_length);
    cursor += mp_sockets[sockfd].session.local_pub_key_length;

    memcpy(cursor, mp_sockets[sockfd].session.remote_nonce, SESSION_NONCE_LENGTH);
    cursor += SESSION_NONCE_LENGTH;

    memcpy(cursor, mp_sockets[sockfd].session.remote_pub_key,
            mp_sockets[sockfd].session.remote_pub_key_length);

    printf("Session info:");
    hexdump(session, session_length);
    printf("\n");

    // Allocate space for AEAD encryption of session info; using CTR so only need extra tag space
    smkex_pkt* ppkt = smkex_pkt_allocate(session_length + SESSION_TAG_LENGTH);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for session ciphertext.\n");
        return -1;
    }

    // Encrypt using session key (TODO: unsafe, update IV after each encryption)
    int rc = mp_aesgcm_encrypt(session, session_length, mp_sockets[sockfd].session_key,
            mp_sockets[sockfd].iv, ppkt->value, &ppkt->length);
    if (rc < 0) {
        fprintf(stderr, "Error: aesgcm encryption failed.\n");
        return -1;
    }

    // Send network packet containing session info
    ppkt->type = TLV_TYPE_DH;
    ppkt->send = original_send;


    // Block while waiting for slave subflows to be ready
    int slave_count = 2;
    rc = setsockopt(sockfd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD, &slave_count,
        sizeof(int));
    if (rc < 0) {
        fprintf(stderr, "Error: could not set slave threshold.\n");
        return -1;
    }

    // Wait using poll
    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = sockfd;
    fds[0].events |= POLLCONN;
    poll(fds, 1, -1);

    for (int index = 2; index <= slave_count; index++) {
        rc = smkex_pkt_send(ppkt, sockfd, select_subflow(0, index));
        if (rc < 0) {
            fprintf(stderr, "Error: could not send session ciphertext.\n");
            return -1;
        }
    }

    return 0;
}


/*
 * Remote and local are reversed for clients:
 * [ remote_nonce | remote_pub_key | local_nonce | local_pub_key ]
 */
int __recv_check_session_info(int sockfd, int flags) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");

    smkex_pkt* ppkt = smkex_pkt_allocate(0);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate info receive packet.\n");
        return -1;
    }
    ppkt->recv = original_recv;
    int rc = smkex_pkt_recv(ppkt, sockfd, flags);
    if (rc < 0) {
        fprintf(stderr, "Error: could not receive session info packet.\n");
        return -1;
    }

    // Decrypt info
    unsigned char* session_info = malloc(ppkt->length);
    if (session_info == NULL) {
        fprintf(stderr, "Error: could not allocate memory for session info decryption.\n");
        return -1;
    }
    size_t session_info_length;
    rc = mp_aesgcm_decrypt(ppkt->value, ppkt->length, mp_sockets[sockfd].session_key,
            mp_sockets[sockfd].iv, session_info, &session_info_length);
    if (rc < 0) {
        fprintf(stderr, "Error: session info decryption failed.\n");
        return -1;
    }

    printf("Session info:");
    hexdump(session_info, session_info_length);
    printf("\n");

    // Compare values
    unsigned char* cursor = session_info;
    rc = memcmp(cursor, mp_sockets[sockfd].session.remote_nonce, SESSION_NONCE_LENGTH);
    if (rc != 0) {
        fprintf(stderr, "Remote nonce mismsatch.\n");
        return -1;
    }
    cursor += SESSION_NONCE_LENGTH;

    rc = memcmp(cursor, mp_sockets[sockfd].session.remote_pub_key,
            mp_sockets[sockfd].session.remote_pub_key_length);
    if (rc != 0) {
        fprintf(stderr, "Remote pub key mismsatch.\n");
        return -1;
    }
    cursor += mp_sockets[sockfd].session.remote_pub_key_length;

    rc = memcmp(cursor, mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH);
    if (rc != 0) {
        fprintf(stderr, "Local nonce mismsatch.\n");
        return -1;
    }
    cursor += SESSION_NONCE_LENGTH;

    rc = memcmp(cursor, mp_sockets[sockfd].session.local_pub_key,
            mp_sockets[sockfd].session.local_pub_key_length);
    if (rc != 0) {
        fprintf(stderr, "Local pub key mismsatch.\n");
        return -1;
    }

    return 0;
}


EC_POINT* __recv_remote_key(int sockfd, EC_KEY* key) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");

    // Get a new message from sockfd
    smkex_pkt* ppkt = smkex_pkt_allocate(0);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for client pkt.\n");
        return NULL;
    }

    ppkt->recv = original_recv;
    int rc = smkex_pkt_recv(ppkt, sockfd, 0);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not get remote public key.\n");
        return NULL;
    }

    // Allocate new point for remote public key
    const EC_GROUP* ec_group = EC_KEY_get0_group(key);
    EC_POINT* remote_pub_key = EC_POINT_new(ec_group);
    if (remote_pub_key == NULL) {
       fprintf(stderr, "Error: Could not create point for remote public key.\n");
       return NULL;
    }

    // Get remote nonce
    mp_sockets[sockfd].session.remote_nonce = malloc(SESSION_NONCE_LENGTH);
    if (mp_sockets[sockfd].session.remote_nonce == NULL) {
        fprintf(stderr, "Error: could not allocate memory for remote nonce.\n");
        return NULL;
    }

    memcpy(mp_sockets[sockfd].session.remote_nonce, ppkt->value, SESSION_NONCE_LENGTH);

    // Extract public key bytestream, skip nonce bytes
    size_t remote_pub_key_length = ppkt->length - SESSION_NONCE_LENGTH;
    mp_sockets[sockfd].session.remote_pub_key = malloc(remote_pub_key_length);
    mp_sockets[sockfd].session.remote_pub_key_length = remote_pub_key_length;
    if (mp_sockets[sockfd].session.remote_pub_key == NULL) {
        fprintf(stderr, "Error: could not allocate memory for remote public key.\n");
        return NULL;
    }
    memcpy(mp_sockets[sockfd].session.remote_pub_key, ppkt->value + SESSION_NONCE_LENGTH,
            remote_pub_key_length);

    EC_POINT_oct2point(ec_group, remote_pub_key, mp_sockets[sockfd].session.remote_pub_key,
                remote_pub_key_length, NULL);
    if (remote_pub_key == NULL) {
        fprintf(stderr, "Error: Could not convert remote public key to point.\n");
        return NULL;
    }

    return remote_pub_key;
}


int connect(int sockfd, const struct sockaddr* address, socklen_t address_len) {
    int (*original_connect)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "connect");
    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        printf("Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

    int rc = original_connect(sockfd, address, address_len);
    if (rc >= 0) {
        mp_sockets[sockfd].used = 1;
        mp_sockets[sockfd].recv_buffer = NULL;
        mp_sockets[sockfd].recv_buffer_cursor = NULL;
        mp_sockets[sockfd].recv_stored_ppkt = NULL;
        mp_sockets[sockfd].recv_remaining = 0;
        memset(&mp_sockets[sockfd].session, 0, sizeof(mp_sockets[sockfd].session));
    }

    // Run ECDH key exchange
    EC_KEY* ec_key = __new_key_pair();
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not generate local key pair.\n");
        return -1;
    }

    rc = __send_local_key(sockfd, ec_key);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send local public key.\n");
        return -1;
    }

    EC_POINT* remote_pub_key = __recv_remote_key(sockfd, ec_key);
    if (remote_pub_key == NULL) {
        fprintf(stderr, "Error: Could not receive remote public key. \n");
        return -1;
    }

    // Compute session key
    mp_sockets[sockfd].session_key = malloc(SESSION_KEY_LENGTH);
    if (mp_sockets[sockfd].session_key == NULL) {
        perror("malloc");
        return -1;
    }
    rc = ECDH_compute_key(mp_sockets[sockfd].session_key, SESSION_KEY_LENGTH,
            remote_pub_key, ec_key, nist_800_kdf);
    if (rc == 0) {
        fprintf(stderr, "Error: Could not compute shared secret. \n");
        return -1;
    }

    // TODO DEBUG
    printf("Key = ");
    hexdump(mp_sockets[sockfd].session_key, SESSION_KEY_LENGTH);
    printf("\n");
    memset(mp_sockets[sockfd].session_key, 0, SESSION_KEY_LENGTH);

    mp_sockets[sockfd].iv = malloc(SESSION_IV_LENGTH);
    if (mp_sockets[sockfd].iv == NULL) {
        perror("malloc");
        return -1;
    }
    memset(mp_sockets[sockfd].iv, 0, SESSION_IV_LENGTH);

    // TODO DEBUG
    printf("Session local nonce = ");
    hexdump(mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH);
    printf("\n");
    printf("Session remote nonce = ");
    hexdump(mp_sockets[sockfd].session.remote_nonce, SESSION_NONCE_LENGTH);
    printf("\n");

    printf("Session local pubkey = ");
    hexdump(mp_sockets[sockfd].session.local_pub_key,
            mp_sockets[sockfd].session.local_pub_key_length);
    printf("\n");
    printf("Session remote pubkey = ");
    hexdump(mp_sockets[sockfd].session.remote_pub_key,
            mp_sockets[sockfd].session.remote_pub_key_length);
    printf("\n");

    // Block while waiting for slave subflows to be ready
    int slave_count = 2;
    rc = setsockopt(sockfd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD, &slave_count,
        sizeof(int));
    if (rc < 0) {
        fprintf(stderr, "Error: could not set slave threshold.\n");
        return -1;
    }

    // Wait using poll
    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = sockfd;
    fds[0].events |= POLLCONN;
    poll(fds, 1, -1);

    for (int index = 2; index <= slave_count; index++) {
        rc = __recv_check_session_info(sockfd, select_subflow(0, index));
        if (rc < 0) {
            fprintf(stderr, "Error: session info check failed.\n");
            return -1;
        }
    }

    return rc;
}


int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    int (*original_accept)(int, struct sockaddr*, socklen_t*) = dlsym(RTLD_NEXT, "accept");
    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

    int accepted_fd = original_accept(sockfd, addr, addrlen);
    if (accepted_fd >= 0) {
        mp_sockets[accepted_fd].used = 1;
        mp_sockets[accepted_fd].recv_buffer = NULL;
        mp_sockets[accepted_fd].recv_buffer_cursor = NULL;
        mp_sockets[accepted_fd].recv_stored_ppkt = NULL;
        mp_sockets[accepted_fd].recv_remaining = 0;
        memset(&mp_sockets[sockfd].session, 0, sizeof(mp_sockets[sockfd].session));
    }

    // Perform DH key exchange
    EC_KEY* ec_key = __new_key_pair();
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not generate local key pair.\n");
        return -1;
    }

    int rc = __send_local_key(accepted_fd, ec_key);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send local public key.\n");
        return -1;
    }

    EC_POINT* remote_pub_key = __recv_remote_key(accepted_fd, ec_key);
    if (remote_pub_key == NULL) {
        fprintf(stderr, "Error: Could not receive remote public key. \n");
        return -1;
    }

    // Compute session key
    mp_sockets[accepted_fd].session_key = malloc(SESSION_KEY_LENGTH);
    if (mp_sockets[accepted_fd].session_key == NULL) {
        perror("malloc");
        return -1;
    }
    rc = ECDH_compute_key(mp_sockets[accepted_fd].session_key, SESSION_KEY_LENGTH,
            remote_pub_key, ec_key, nist_800_kdf);
    if (rc == 0) {
        fprintf(stderr, "Error: Could not compute shared secret. \n");
        return -1;
    }

    // TODO DEBUG
    printf("Key = ");
    hexdump(mp_sockets[accepted_fd].session_key, SESSION_KEY_LENGTH);
    printf("\n");
    memset(mp_sockets[accepted_fd].session_key, 0, SESSION_KEY_LENGTH);


    mp_sockets[accepted_fd].iv = malloc(SESSION_IV_LENGTH);
    if (mp_sockets[accepted_fd].iv == NULL) {
        perror("malloc");
        return -1;
    }
    memset(mp_sockets[accepted_fd].iv, 0, SESSION_IV_LENGTH);

    // TODO DEBUG
    printf("Session local nonce = ");
    hexdump(mp_sockets[accepted_fd].session.local_nonce, SESSION_NONCE_LENGTH);
    printf("\n");
    printf("Session remote nonce = ");
    hexdump(mp_sockets[accepted_fd].session.remote_nonce, SESSION_NONCE_LENGTH);
    printf("\n");

    printf("Session local pubkey = ");
    hexdump(mp_sockets[accepted_fd].session.local_pub_key,
            mp_sockets[accepted_fd].session.local_pub_key_length);
    printf("\n");
    printf("Session remote pubkey = ");
    hexdump(mp_sockets[accepted_fd].session.remote_pub_key,
            mp_sockets[accepted_fd].session.remote_pub_key_length);
    printf("\n");

    
    rc = __send_session_info(accepted_fd);
    if (rc < 0) {
        fprintf(stderr, "Error: could not send session info.\n");
        return -1;
    }

    return accepted_fd;
}


ssize_t send(int sockfd, const void* buf, size_t len, int flags) {
    ssize_t (*original_send)(int, const void*, size_t, int) = dlsym(RTLD_NEXT, "send");
    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

    // Encrypt
    uint32_t max_ciphertext_length = len + EVP_MAX_IV_LENGTH + EVP_MAX_BLOCK_LENGTH +
                                        SESSION_TAG_LENGTH;
    smkex_pkt* ppkt = smkex_pkt_allocate(max_ciphertext_length);
    if (ppkt == NULL) {
        return -1;
    }

    ppkt->type = TLV_TYPE_DATA;
    mp_aesgcm_encrypt(buf, len, mp_sockets[sockfd].session_key, mp_sockets[sockfd].iv,
        ppkt->value, &ppkt->length);
    ppkt->send = original_send;
    smkex_pkt_send(ppkt, sockfd, flags);
    smkex_pkt_free(ppkt);
    return len;
}


ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");
    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }


    if (mp_sockets[sockfd].recv_remaining == 0) {
        // App requested bytes, but we have none available
        // Receive a new packet
        smkex_pkt* ppkt = smkex_pkt_allocate(0);
        if (ppkt == NULL) {
            return -1;
        }
        ppkt->recv = original_recv;
        smkex_pkt_recv(ppkt, sockfd, flags);

        if (ppkt->type != TLV_TYPE_DATA) {
            // Bad type means we cannot accept this TLV
            fprintf(stderr, "Error: received type = %d, was expecting %d.\n", ppkt->type, TLV_TYPE_DATA);
            return -1;
        }

        // Decrypt
        mp_sockets[sockfd].recv_buffer = malloc(ppkt->length); // Will be smaller
        if (mp_sockets[sockfd].recv_buffer == NULL) {
            perror("malloc");
            return -1;
        }

        mp_aesgcm_decrypt(ppkt->value, ppkt->length, mp_sockets[sockfd].session_key,
                mp_sockets[sockfd].iv, mp_sockets[sockfd].recv_buffer,
                &mp_sockets[sockfd].recv_remaining);

        // Initialize receive cursor and length of available data
        mp_sockets[sockfd].recv_buffer_cursor = mp_sockets[sockfd].recv_buffer;
        mp_sockets[sockfd].recv_stored_ppkt = ppkt;
    }

    if (mp_sockets[sockfd].recv_remaining > 0) {
        // If there are plaintext bytes from a previous decryption remaining, use those
        if (len >= mp_sockets[sockfd].recv_remaining) {
            // App asked for more bytes than we have, send as much as we have
            memcpy(buf, mp_sockets[sockfd].recv_buffer_cursor, mp_sockets[sockfd].recv_remaining);

            // Sent all bytes in the current decryption, free stored resources
            smkex_pkt_free(mp_sockets[sockfd].recv_stored_ppkt);

            ssize_t received = mp_sockets[sockfd].recv_remaining;
            mp_sockets[sockfd].recv_remaining = 0;
            return received;
        } else {
            // App asked for less bytes than we have, send them all and move cursor
            memcpy(buf, mp_sockets[sockfd].recv_buffer_cursor, len);
            mp_sockets[sockfd].recv_buffer_cursor += len;
            mp_sockets[sockfd].recv_remaining -= len;

            return len;
        }
    }
}


int close(int fd) {
    int (*original_close)(int) = dlsym(RTLD_NEXT, "close");
    int initialize();

    if (fd < 0 || fd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported fd = %d.\n", fd);
        errno = EBADF;
        return -1;
    }

    int rc = original_close(fd);
    if (mp_sockets[fd].used == 1 && rc >= 0) {
        mp_sockets[fd].used = 0;
    }
    return rc;
}
