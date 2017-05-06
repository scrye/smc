#include "pkt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

smkex_pkt* __smkex_pkt_new(void) {
    smkex_pkt* ppkt = malloc(sizeof(smkex_pkt));
    if (ppkt == NULL) {
        perror("malloc");
        return NULL;
    }

    ppkt->__capacity = 0;
    ppkt->__raw_smkex_ppkt = NULL;

    ppkt->length = 0;
    ppkt->type = 0;
    ppkt->value = NULL;
    ppkt->recv = NULL;
    ppkt->send = NULL;
    ppkt->header_size = sizeof(ppkt->__raw_smkex_ppkt->type) +
                        sizeof(ppkt->__raw_smkex_ppkt->length);

    return ppkt;
}


smkex_pkt* smkex_pkt_allocate(size_t capacity) {
    smkex_pkt* ppkt = __smkex_pkt_new();

    if (capacity == 0) {
        // Nothing to do
        return ppkt;
    }

    size_t total_raw_size = ppkt->header_size + capacity;
    ppkt->__raw_smkex_ppkt = malloc(total_raw_size);
    if (ppkt->__raw_smkex_ppkt == NULL) {
        perror("malloc");
        return NULL;
    } else {
        ppkt->value = ppkt->__raw_smkex_ppkt->value;
        ppkt->__capacity = capacity;
        return ppkt;
    }
}


ssize_t smkex_pkt_send(smkex_pkt* ppkt, int sockfd, int flags) {
    // Prepare raw packet
    ppkt->__raw_smkex_ppkt->type = htonl(ppkt->type);
    ppkt->__raw_smkex_ppkt->length = htonl(ppkt->length);

    // Send bytes
    unsigned char * buffer = (unsigned char*)ppkt->__raw_smkex_ppkt;
    size_t bytes_sent = 0;
    size_t bytes_to_send = ppkt->header_size + ppkt->length;
    while (bytes_sent != bytes_to_send) {
        ssize_t count = ppkt->send(sockfd, buffer + bytes_sent, bytes_to_send - bytes_sent, flags);
        if (count < 0) {
            perror("send");
            return count;
        }

        bytes_sent += count;
    }

    return bytes_sent;
}


ssize_t smkex_pkt_recv(smkex_pkt* ppkt, int sockfd, int flags) {

    // Receive header
    size_t header_size = sizeof(ppkt->__raw_smkex_ppkt->type) +
                         sizeof(ppkt->__raw_smkex_ppkt->length);
    unsigned char header[header_size];

    size_t bytes_recvd = 0;
    while (bytes_recvd != header_size) {
        ssize_t count = ppkt->recv(sockfd, &header[bytes_recvd], header_size - bytes_recvd, flags);
        if (count < 0) {
            perror("recv");
            return count;
        }

        bytes_recvd += count;
    }

    // Extract header fields
    ppkt->length = ntohl(*(uint32_t*)&header[sizeof(ppkt->__raw_smkex_ppkt->type)]);
    ppkt->type = ntohl(*(uint32_t*)&header[0]);

    ppkt->__raw_smkex_ppkt = malloc(header_size + ppkt->length);
    if (ppkt->__raw_smkex_ppkt == NULL) {
        perror("malloc");
        return -1;
    }
    ppkt->value = ppkt->__raw_smkex_ppkt->value;
    memcpy(ppkt->__raw_smkex_ppkt, &header[0], header_size);

    // Receive raw packet
    unsigned char* buffer = ppkt->value;
    bytes_recvd = 0;
    while (bytes_recvd != ppkt->length) {
        ssize_t count = ppkt->recv(sockfd, buffer + bytes_recvd, ppkt->length - bytes_recvd, flags);
        if (count < 0) {
            perror("recv");
            return count;
        }
        bytes_recvd += count;
    }


    return bytes_recvd + header_size;
}


void smkex_pkt_free(smkex_pkt* ppkt) {
    free(ppkt->__raw_smkex_ppkt);
    free(ppkt);
}
