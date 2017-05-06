#include <sys/types.h>
#include <stdint.h>

#ifndef PKT_H
#define PKT_H

enum {
  TLV_TYPE_DH = 0,
  TLV_TYPE_DATA = 1
};

typedef struct {
    size_t __capacity;     // capacity of value field in host byte order
    size_t length;         // length of value field in host byte order
    size_t header_size;
    uint32_t type;
    unsigned char* value;  // Never change this pointer directly
    ssize_t (*recv)(int, void *, size_t, int);
    ssize_t (*send)(int, const void *, size_t, int);

    struct {
        uint32_t type;   // stored in network byte order
        uint32_t length; // stored in network byte order
        unsigned char value[];
    } __attribute__((packed))* __raw_smkex_ppkt;
} smkex_pkt;

smkex_pkt* smkex_pkt_allocate(size_t capacity);
ssize_t smkex_pkt_send(smkex_pkt* ppkt, int sockfd, int flags);
ssize_t smkex_pkt_recv(smkex_pkt* ppkt, int sockfd, int flags);
void smkex_pkt_free(smkex_pkt* ppkt);

#endif
