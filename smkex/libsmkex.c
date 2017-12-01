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
#include <fcntl.h>
#include <stdarg.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

#define SMKEX_MAX_FD    1024
#define SO_SMKEX_NOCRYPT 0xA001

#define DEBUG 0
#define SMKEX 0

#define POLLCONN    0x800

FILE *dbfile;
#define dbgtext(x)\
  fprintf(dbfile, (x));



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

    int connected; // for client socket
    int accepted;  // for server socket
    //int req_noblock; // signal fcntl(...,O_NONBLOCK) request
    int no_crypt; // to signal that we want a standard TCP connection (no encryption)
    int do_session_attack; // used to simulate attacker
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


int __send_local_key(int sockfd, EC_KEY* key, int ids) {
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

#if DEBUG
    fprintf(stderr, "Sending local key on socket %d, subflow %d\n",
        sockfd, ids);
#endif
    // Public keys are always sent on the master subflow
    rc = smkex_pkt_send(ppkt, sockfd, select_subflow(0, ids));
    smkex_pkt_free(ppkt);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send our public key.\n");
        return -1;
    }

    return 0;
}

int __send_dummy(int sockfd) {
    ssize_t (*original_send)(int, const void*, size_t, int) = dlsym(RTLD_NEXT, "send");

    // Prepare message
    smkex_pkt* ppkt = smkex_pkt_allocate(1);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for server pkt.\n");
        return -1;
    }

    memset(ppkt->value, 0, 1);

    ppkt->type = TLV_TYPE_DUMMY;
    ppkt->length = 1;
    ppkt->send = original_send;

    // Send on any flow
    int rc = smkex_pkt_send(ppkt, sockfd, 0);
    smkex_pkt_free(ppkt);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send dummy packet.\n");
        return -1;
    }

    return 0;
}


/*
 * Format is:
 * [ local_nonce | local_pub_key | remote_nonce | remote_pub_key ]
 */
int __send_session_info(int sockfd, int ids) {
    ssize_t (*original_send)(int, const void*, size_t, int) = dlsym(RTLD_NEXT, "send");
    int (*original_setsockopt)(int, int, int, const void*, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");

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
        smkex_pkt_free(ppkt);
        return -1;
    }

    // Send network packet containing session info
    ppkt->type = TLV_TYPE_DH;
    ppkt->send = original_send;

    // Perform hack on first byte of session_info data if we are
    // simulating an attacker
    if(mp_sockets[sockfd].do_session_attack)
    {
      fprintf(stderr, "[server] Hacking session info value...\n");
      ppkt->value[3] ^= 0xAA;
    }

#if DEBUG
    fprintf(stderr, "Sending session info on socket %d, subflow %d\n",
        sockfd, ids);
#endif
    // Send session info on secondary channel
    rc = smkex_pkt_send(ppkt, sockfd, select_subflow(0, ids));
    smkex_pkt_free(ppkt);
    if (rc < 0) {
        fprintf(stderr, "Error: could not send session ciphertext.\n");
        return -1;
    }

    return 0;
}


/*
 * Remote and local are reversed for clients:
 * [ remote_nonce | remote_pub_key | local_nonce | local_pub_key ]
 */
int __recv_check_session_info(int sockfd, int ids) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");
    int retval = 0;

    smkex_pkt* ppkt = smkex_pkt_allocate(0);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate info receive packet.\n");
        return -1;
    }
    ppkt->recv = original_recv;
#if DEBUG
    fprintf(stderr, "Receiving session info on socket %d, subflow %d\n",
        sockfd, ids);
#endif
    // TODO: fix this code once kernel code is fixed
    int rc = smkex_pkt_recv(ppkt, sockfd, 0);  // Just a hack for now, until we solve kernel issue
    //int rc = smkex_pkt_recv(ppkt, sockfd, select_subflow(0, ids)); // This should be used when kernel code is fine
    if (rc <= 0) {
        fprintf(stderr, "Error: could not receive session info packet.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }

    // Decrypt info
    unsigned char* session_info = malloc(ppkt->length);
    if (session_info == NULL) {
        fprintf(stderr, "Error: could not allocate memory for session info decryption.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }
    size_t session_info_length;
    rc = mp_aesgcm_decrypt(ppkt->value, ppkt->length, mp_sockets[sockfd].session_key,
            mp_sockets[sockfd].iv, session_info, &session_info_length);
    if (rc < 0) {
        fprintf(stderr, "Error: session info decryption failed.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }

    printf("Session info:");
    hexdump(session_info, session_info_length);
    printf("\n");

    // Compare values
    unsigned char* cursor = session_info;
    rc = memcmp(cursor, mp_sockets[sockfd].session.remote_nonce, SESSION_NONCE_LENGTH);
    if (rc != 0) {
        fprintf(stderr, "Remote nonce mismsatch.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }
    cursor += SESSION_NONCE_LENGTH;

    rc = memcmp(cursor, mp_sockets[sockfd].session.remote_pub_key,
            mp_sockets[sockfd].session.remote_pub_key_length);
    if (rc != 0) {
        fprintf(stderr, "Remote pub key mismsatch.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }
    cursor += mp_sockets[sockfd].session.remote_pub_key_length;

    rc = memcmp(cursor, mp_sockets[sockfd].session.local_nonce, SESSION_NONCE_LENGTH);
    if (rc != 0) {
        fprintf(stderr, "Local nonce mismsatch.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }
    cursor += SESSION_NONCE_LENGTH;

    rc = memcmp(cursor, mp_sockets[sockfd].session.local_pub_key,
            mp_sockets[sockfd].session.local_pub_key_length);
    if (rc != 0) {
        fprintf(stderr, "Local pub key mismsatch.\n");
        retval = -1;
        goto free_ppkt_recv_check_si;
    }

free_ppkt_recv_check_si:
    smkex_pkt_free(ppkt);
    return retval;
}


EC_POINT* __recv_remote_key(int sockfd, EC_KEY* key, int ids) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");

    // Get a new message from sockfd
    smkex_pkt* ppkt = smkex_pkt_allocate(0);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for client pkt.\n");
        return NULL;
    }

#if DEBUG
    fprintf(stderr, "Receiving remote key on socket %d, subflow %d\n",
        sockfd, ids);
#endif
    // TODO: fix this code once kernel code is fixed
    ppkt->recv = original_recv;
    int rc = smkex_pkt_recv(ppkt, sockfd, 0); // Just a hack until we fix kernel issue
    //int rc = smkex_pkt_recv(ppkt, sockfd, select_subflow(0, ids)); This should be used once kernel code is fixed
    if (rc <= 0) {
        fprintf(stderr, "Error: Could not get remote public key.\n");
        goto err_recv_remotekey;
    }

    // Allocate new point for remote public key
    const EC_GROUP* ec_group = EC_KEY_get0_group(key);
    EC_POINT* remote_pub_key = EC_POINT_new(ec_group);
    if (remote_pub_key == NULL) {
        fprintf(stderr, "Error: Could not create point for remote public key.\n");
        goto err_recv_remotekey;
    }

    // Get remote nonce
    mp_sockets[sockfd].session.remote_nonce = malloc(SESSION_NONCE_LENGTH);
    if (mp_sockets[sockfd].session.remote_nonce == NULL) {
        fprintf(stderr, "Error: could not allocate memory for remote nonce.\n");
        goto err_recv_remotekey2;
    }

    memcpy(mp_sockets[sockfd].session.remote_nonce, ppkt->value, SESSION_NONCE_LENGTH);

    // Extract public key bytestream, skip nonce bytes
    size_t remote_pub_key_length = ppkt->length - SESSION_NONCE_LENGTH;
    mp_sockets[sockfd].session.remote_pub_key = malloc(remote_pub_key_length);
    mp_sockets[sockfd].session.remote_pub_key_length = remote_pub_key_length;
    if (mp_sockets[sockfd].session.remote_pub_key == NULL) {
        fprintf(stderr, "Error: could not allocate memory for remote public key.\n");
        goto err_recv_remotekey3;
    }
    memcpy(mp_sockets[sockfd].session.remote_pub_key, ppkt->value + SESSION_NONCE_LENGTH,
            remote_pub_key_length);

    EC_POINT_oct2point(ec_group, remote_pub_key, mp_sockets[sockfd].session.remote_pub_key,
                remote_pub_key_length, NULL);
    if (remote_pub_key == NULL) {
        fprintf(stderr, "Error: Could not convert remote public key to point.\n");
        goto err_recv_remotekey4;
    }

    smkex_pkt_free(ppkt);
    return remote_pub_key;

err_recv_remotekey4:
    free(mp_sockets[sockfd].session.remote_pub_key);
    mp_sockets[sockfd].session.remote_pub_key = NULL;

err_recv_remotekey3:
    free(mp_sockets[sockfd].session.remote_nonce);
    mp_sockets[sockfd].session.remote_nonce = NULL;

err_recv_remotekey2:
    EC_POINT_free(remote_pub_key);

err_recv_remotekey:
    smkex_pkt_free(ppkt);

    return NULL;
}

int __recv_dummy(int sockfd) {
    ssize_t (*original_recv)(int, void*, size_t, int) = dlsym(RTLD_NEXT, "recv");

    // Get a new message from sockfd
    smkex_pkt* ppkt = smkex_pkt_allocate(0);
    if (ppkt == NULL) {
        fprintf(stderr, "Error: could not allocate memory for client pkt.\n");
        return -1;
    }

    // Get dummy packet on whatever channel is available
    ppkt->recv = original_recv;
    int rc = smkex_pkt_recv(ppkt, sockfd, 0);
    if (rc <= 0) {
        fprintf(stderr, "Error: Could not get dummy packet.\n");
        return -1;
    }

    // Discard dummy packet
    smkex_pkt_free(ppkt);

    return 0;
}

int connect(int sockfd, const struct sockaddr* address, socklen_t address_len) {
    int (*original_connect)(int, const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "connect");
    //int (*original_fcntl)(int, int, int) = dlsym(RTLD_NEXT, "fcntl");
    int (*original_setsockopt)(int, int, int, const void*, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");
    int (*original_fcntl)(int, int, ...) = dlsym(RTLD_NEXT, "fcntl");
    __initialize();
    int ids0, ids1;

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

#if DEBUG
    fprintf(stderr, "libsmkex: starting connect on socket %d\n", sockfd);

    int flags = original_fcntl(sockfd, F_GETFL, 0);
    fprintf(stderr, "O_NONBLOCK in flags of connect() on libsmkex: %d\n", flags & O_NONBLOCK);
#endif

    int rc = original_connect(sockfd, address, address_len);
    if (rc >= 0) {
        mp_sockets[sockfd].used = 1;
        mp_sockets[sockfd].recv_buffer = NULL;
        mp_sockets[sockfd].recv_buffer_cursor = NULL;
        mp_sockets[sockfd].recv_stored_ppkt = NULL;
        mp_sockets[sockfd].recv_remaining = 0;
        memset(&mp_sockets[sockfd].session, 0, sizeof(mp_sockets[sockfd].session));
    }

    if (mp_sockets[sockfd].no_crypt)
    {
#if DEBUG
    fprintf(stderr, "libsmkex: connecting without crypto on socket %d\n", sockfd);
#endif
      goto connect_no_crypt;
    }

#if SMKEX // Don't care about subflows, blocking or dummy packets
    // Send dummy packet to force creating two subflows
    rc = __send_dummy(sockfd);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send dummy packet.\n");
        return -1;
    }

    // Block while waiting for slave subflows to be ready
    int slave_count = 2;
    rc = original_setsockopt(sockfd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD, &slave_count,
        sizeof(int));
    if (rc < 0) {
        fprintf(stderr, "Error: could not set slave threshold.\n");
        return -1;
    }

#if DEBUG
    fprintf(stderr, "Connect: before poll on socket %d\n", sockfd);
#endif

    // Wait using poll
    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = sockfd;
    fds[0].events |= POLLCONN;
    poll(fds, 1, -1);

#if DEBUG
    fprintf(stderr, "Connect: after poll on socket %d\n", sockfd);
    flags = original_fcntl(sockfd, F_GETFL, 0);
    fprintf(stderr, "O_NONBLOCK in flags of connect() on libsmkex: %d\n", flags & O_NONBLOCK);
#endif

    // check number of existing subflows (needed next)
    int cnt_subflows=0;
    socklen_t len_sockopt=1;
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &cnt_subflows, &len_sockopt);
    if(rc < 0)
    {
        fprintf(stderr, "Error: could not retrieve number of MPTCP flows with getsockopt.\n");
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned %d available subflows\n", cnt_subflows);
#endif


    // Find IDs of subflows
    struct mptcp_sub_ids *ids;
    socklen_t ids_len;
    ids_len = sizeof(struct mptcp_sub_ids) + sizeof(struct mptcp_sub_status) * (cnt_subflows+1);
    ids = (struct mptcp_sub_ids *)malloc(ids_len);
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_IDS, ids, &ids_len);
    ids0 = ids->sub_status[0].id;
    ids1 = ids->sub_status[1].id;
    if(rc < 0)
    {
        fprintf(stderr, "Error %d: could not retrieve MPTCP subflow IDs with getsockopt.\n", rc);
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned the following IDs for the first two sub-flows: ID1: %d; ID2: %d.\n",
        ids->sub_status[0].id, ids->sub_status[1].id);
#endif
#endif //SMKEX

    // Run ECDH key exchange
    EC_KEY* ec_key = __new_key_pair();
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not generate local key pair.\n");
        return -1;
    }

    // Public keys sent on the master subflow
    rc = __send_local_key(sockfd, ec_key, ids0);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send local public key.\n");
        return -1;
    }

    // Public keys received on the master subflow
    EC_POINT* remote_pub_key = __recv_remote_key(sockfd, ec_key, ids0);
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

	// Only run the code below in SMKEX exchanges
#if SMKEX
    // First check number of existing subflows (needed next)
    cnt_subflows=0;
    len_sockopt=1;
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &cnt_subflows, &len_sockopt);
    if(rc < 0)
    {
        fprintf(stderr, "Error: could not retrieve number of MPTCP flows with getsockopt.\n");
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned %d available subflows\n", cnt_subflows);
#endif


    // Find IDs of subflows
    //struct mptcp_sub_ids *ids;
    //socklen_t ids_len;
    ids_len = sizeof(struct mptcp_sub_ids) + sizeof(struct mptcp_sub_status) * (cnt_subflows+1);
    ids = (struct mptcp_sub_ids *)malloc(ids_len);
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_IDS, ids, &ids_len);
    if(rc < 0)
    {
        fprintf(stderr, "Error %d: could not retrieve MPTCP subflow IDs with getsockopt.\n", rc);
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned the following IDs for the first two sub-flows: ID1: %d; ID2: %d.\n",
        ids->sub_status[0].id, ids->sub_status[1].id);
#endif // DEBUG

    // Receive session info on secondary channel
    rc = __recv_check_session_info(sockfd, ids1);
    if (rc < 0) {
        fprintf(stderr, "Error: session info check failed.\n");
        return -1;
    }
#endif // SMKEX

#if DEBUG
    fprintf(stderr, "Connect: after receiving session info on socket %d\n", sockfd);
#endif

connect_no_crypt:
    mp_sockets[sockfd].connected = 1;

#if DEBUG
    fprintf(stderr, "libsmkex: finishing connect on socket %d\n", sockfd);
#endif

    return rc;
}

/*
 * Bind method for SMKEX.
 * Used mainly to reproduce an active attacker for some local ports
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    int (*original_bind)(int , const struct sockaddr*, socklen_t) = dlsym(RTLD_NEXT, "bind");

    // Perform attack if server port is 12345 or 12346 (values below in hton order)
    if (((struct sockaddr_in*)addr)->sin_port == 14640 || ((struct sockaddr_in*)addr)->sin_port == 14896)
    {
      fprintf(stderr, "[server] will perform attack on session info for socket %d\n", sockfd);
      mp_sockets[sockfd].do_session_attack = 1;
    }
    else{
      mp_sockets[sockfd].do_session_attack = 0;
    }

    return original_bind(sockfd, addr, addrlen);
}

/*
 * Accept method for SMKEX.
 * This performs the SMKEX protocol before releasing the client socket.
 */
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    int (*original_accept)(int, struct sockaddr*, socklen_t*) = dlsym(RTLD_NEXT, "accept");
    int (*original_setsockopt)(int, int, int, const void*, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");
    __initialize();
    int ids0, ids1;
	int rc;

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

#if DEBUG
    fprintf(stderr, "libsmkex: starting accept on socket %d\n", sockfd);
#endif

    int accepted_fd = original_accept(sockfd, addr, addrlen);
    if (accepted_fd >= 0) {
        mp_sockets[accepted_fd].used = 1;
        mp_sockets[accepted_fd].recv_buffer = NULL;
        mp_sockets[accepted_fd].recv_buffer_cursor = NULL;
        mp_sockets[accepted_fd].recv_stored_ppkt = NULL;
        mp_sockets[accepted_fd].recv_remaining = 0;
        mp_sockets[accepted_fd].no_crypt = mp_sockets[sockfd].no_crypt;
        memset(&mp_sockets[sockfd].session, 0, sizeof(mp_sockets[sockfd].session));
    }


    if (mp_sockets[sockfd].no_crypt)
    {
#if DEBUG
      fprintf(stderr, "libsmkex: accepting without crypto on socket %d\n", accepted_fd);
#endif
      goto accept_no_crypt;
    }

#if SMKEX // We don't care about subflows, synchronization or dummy packets
    // Receive dummy packet to force creating two subflows
    rc = __recv_dummy(accepted_fd);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not receive dummy packet.\n");
        return -1;
    }

    // Block while waiting for slave subflows to be ready
    int slave_count = 2;
    rc = original_setsockopt(accepted_fd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD,
        &slave_count, sizeof(int));
    if (rc < 0) {
        fprintf(stderr, "Error: could not set slave threshold.\n");
        return -1;
    }

#if DEBUG
    fprintf(stderr, "accept: before poll on socket %d\n", accepted_fd);
#endif

    // Wait using poll
    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = accepted_fd;
    fds[0].events |= POLLCONN;
    poll(fds, 1, -1);

#if DEBUG
    fprintf(stderr, "accept: after poll on socket %d\n", accepted_fd);
#endif

    // check number of existing subflows (needed next)
    int cnt_subflows=0;
    socklen_t len_sockopt=1;
    rc = getsockopt(accepted_fd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT,
                    &cnt_subflows, &len_sockopt);
    if(rc < 0)
    {
        fprintf(stderr, "Error: could not retrieve number of MPTCP flows with getsockopt.\n");
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned %d available subflows\n", cnt_subflows);
#endif


    // Find IDs of subflows
    struct mptcp_sub_ids *ids;
    socklen_t ids_len;
    ids_len = sizeof(struct mptcp_sub_ids) + sizeof(struct mptcp_sub_status) * (cnt_subflows+1);
    ids = (struct mptcp_sub_ids *)malloc(ids_len);
    rc = getsockopt(accepted_fd, IPPROTO_TCP, MPTCP_GET_SUB_IDS, ids, &ids_len);
    ids0 = ids->sub_status[0].id;
    ids1 = ids->sub_status[1].id;
    if(rc < 0)
    {
        fprintf(stderr, "Error %d: could not retrieve MPTCP subflow IDs with getsockopt.\n", rc);
        perror("getsockopt");
        return -1;
    }
#if DEBUG
    fprintf(stderr, "MPTCP returned the following IDs for the first two sub-flows: ID1: %d; ID2: %d.\n",
        ids->sub_status[0].id, ids->sub_status[1].id);
#endif
#endif // SMKEX

    // Perform DH key exchange
    EC_KEY* ec_key = __new_key_pair();
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not generate local key pair.\n");
        return -1;
    }

    // Public keys sent on the master subflow
    rc = __send_local_key(accepted_fd, ec_key, ids0);
    if (rc < 0) {
        fprintf(stderr, "Error: Could not send local public key.\n");
        return -1;
    }


    // Public keys received on the master subflow
    EC_POINT* remote_pub_key = __recv_remote_key(accepted_fd, ec_key, ids0);
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


#if SMKEX // Don't send session info when running standard DH
#if DEBUG
    fprintf(stderr, "Accept: before send_session_info() on socket %d\n", accepted_fd);
#endif

    // Set flag to perform hack on first byte of session_info data if we are
    // simulating an attacker
    if(mp_sockets[sockfd].do_session_attack)
      mp_sockets[accepted_fd].do_session_attack = 1;
    else
      mp_sockets[accepted_fd].do_session_attack = 0;
    
    rc = __send_session_info(accepted_fd, ids1);
    if (rc < 0) {
        fprintf(stderr, "Error: could not send session info.\n");
        return -1;
    }

#if DEBUG
    fprintf(stderr, "Accept: after send_session_info() on socket %d\n", accepted_fd);
#endif
#endif // SMKEX

accept_no_crypt:
    mp_sockets[accepted_fd].accepted = 1;

#if DEBUG
    fprintf(stderr, "libsmkex: finishing accept on socket %d\n", sockfd);
#endif

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

#if DEBUG
    fprintf(stderr, "libsmkex: starting send\n");
#endif

    if(mp_sockets[sockfd].no_crypt)
    {
#if DEBUG
      fprintf(stderr, "libsmkex: sending without crypto\n");
#endif
      return original_send(sockfd, buf, len, flags);
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
    int rc;

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

#if DEBUG
    fprintf(stderr, "libsmkex: starting recv on socket %d\n", sockfd);
#endif

    if(mp_sockets[sockfd].no_crypt)
    {
#if DEBUG
      fprintf(stderr, "libsmkex: receiving without crypto on socket %d\n", sockfd);
#endif
      return original_recv(sockfd, buf, len, flags);
    }

    if (mp_sockets[sockfd].recv_remaining == 0) {
        // App requested bytes, but we have none available
        // Receive a new packet
        smkex_pkt* ppkt = smkex_pkt_allocate(0);
        if (ppkt == NULL) {
            return -1;
        }
        ppkt->recv = original_recv;
        rc = smkex_pkt_recv(ppkt, sockfd, flags);
        if (rc <= 0)
        {
            smkex_pkt_free(ppkt);
            return rc; // Could be a non-blocking socket
        }

        if (ppkt->type != TLV_TYPE_DATA) {
            // Bad type means we cannot accept this TLV
            fprintf(stderr, "Error: received type = %d, was expecting %d.\n", ppkt->type, TLV_TYPE_DATA);
            smkex_pkt_free(ppkt);
            return -1;
        }

        // Decrypt
        mp_sockets[sockfd].recv_buffer = malloc(ppkt->length); // Will be smaller
        if (mp_sockets[sockfd].recv_buffer == NULL) {
            perror("malloc");
            smkex_pkt_free(ppkt);
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
	    free(mp_sockets[sockfd].recv_buffer);
            mp_sockets[sockfd].recv_buffer = NULL;
            mp_sockets[sockfd].recv_buffer_cursor = NULL;

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


int fcntl(int sockfd, int cmd, ...) {
    int (*original_fcntl)(int, int, ...) = dlsym(RTLD_NEXT, "fcntl");
    int rc;
    va_list ap;
    int flags;

    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

    va_start(ap, cmd);
    flags = va_arg(ap, int);
    va_end(ap);
    if (-1 == (flags = original_fcntl(sockfd, F_GETFL, 0))) {
      flags = 0;
    }
    int req_noblock = flags & O_NONBLOCK;

#if DEBUG
    fprintf(stderr, "fcntl: cmd %d, flags %d on socket %d\n",
        cmd, flags, sockfd);
    if (req_noblock > 0)
      fprintf(stderr, "fcntl: requesting O_NONBLOCK on socket %d\n", sockfd);
#endif


    return original_fcntl(sockfd, cmd, flags);
}

int setsockopt(int sockfd, int level, int option_name, const void *option_value, socklen_t option_len)
{
    int (*original_setsockopt)(int, int, int, const void*, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");

    __initialize();

    if (sockfd < 0 || sockfd >= SMKEX_MAX_FD) {
        fprintf(stderr, "Error: unsupported socket fd = %d.\n", sockfd);
        errno = EBADF;
        return -1;
    }

#if DEBUG
    fprintf(stderr, "setsockopt: level %d, option_name %d on socket %d\n",
        level, option_name, sockfd);
#endif

    // Check if we are being required to stop crypto.
    if (option_name == SO_SMKEX_NOCRYPT)
    {
#if DEBUG
      fprintf(stderr,
          "Setsockopt: Received request to stop crypto on socket %d\n", sockfd);
#endif
      mp_sockets[sockfd].no_crypt = 1;
      return 0;
    }
    else
    {
      return original_setsockopt(sockfd, level, option_name, option_value, option_len);
    }

}
