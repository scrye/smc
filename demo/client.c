#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <poll.h>

#define DIE(cond, message) do { if (cond) { \
    fprintf(stderr, "%s:%d:", __FILE__, __LINE__);  perror(message); exit(-1);}} while(0)

int select_subflow(int oldflags, int index) {
    int newflags = oldflags;

    unsigned char* p = (unsigned char*)&newflags;
    p[2] |= index;

    return newflags;
}

int main(int argc, char *argv[]) {
    int rc;
    //struct mptcp_sub_ids *ids;

    if (argc != 2) {
        printf("usage: %s <ip of server>\n",argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(sockfd < 0, "socket");

    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    rc = inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);
    DIE(rc <= 0, "inet_pton");

    rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    DIE(rc < 0, "connect");

    int flags = select_subflow(0, 1);
    unsigned char data[2];
    rc = recv(sockfd, data, 2, flags);
    DIE(rc < 0, "recv");
    if (rc == 0) {
        printf("EOF\n");
    }
    printf("Received %c%c on subflow %d.\n", data[0], data[1], 1);

    // Set subflow count threshold
    int threshold = 2;
    rc = setsockopt(sockfd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD, &threshold, sizeof(int));
    DIE(rc < 0, "setsockopt");

    int ret_threshold = 0;
    socklen_t ret_threshold_length = sizeof(ret_threshold);
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_THRESHOLD, &ret_threshold,
        &ret_threshold_length);
    DIE(rc < 0, "getsockopt");

    int count_before = 0;
    socklen_t count_before_length = sizeof(count_before);
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &count_before,
        &count_before_length);
    DIE(rc < 0, "getsockopt");

    printf("Set = %u, Get = %d, Count before = %d\n", threshold, ret_threshold, count_before);

    // Poll for subflow changes
    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = sockfd;
    fds[0].events |= POLLCONN;
    poll(fds, 1, -1);

    int count_after = 0;
    socklen_t count_after_length = sizeof(count_after);
    rc = getsockopt(sockfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &count_after, &count_after_length);
    DIE(rc < 0, "getsockopt");
    printf("Count after = %d\n", count_after);

    int index = 2;
    flags = select_subflow(0, index);
    rc = recv(sockfd, data, 2, flags);
    DIE(rc < 0, "recv");
    if (rc == 0) {
	printf("EOF\n");
    }
    printf("Received %c%c on subflow %d.\n", data[0], data[1], index);

    close(sockfd);
    return 0;
}
