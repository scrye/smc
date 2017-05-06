#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
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


/*
 * Simple server program that sends a single byte one each subflow.
 *
 */

int main(int argc, char *argv[]) {
    int rc;
    //struct mptcp_sub_ids *ids;

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(listenfd < 0, "socket");

    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000);

    rc = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    DIE(rc < 0, "bind");

    rc = listen(listenfd, 10);
    DIE(rc < 0, "listen");

    int acceptfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
    DIE(acceptfd < 0, "accept");

    // Get number of subflows
    int sf_cnt = 0;
    socklen_t length = sizeof(sf_cnt);
    rc = getsockopt(acceptfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &sf_cnt, &length);
    DIE(rc < 0, "getsockopt");
    printf("Number of subflows = %d\n", sf_cnt);

    // Send data on master subflow
    unsigned char data[2];
    data[0] = 'M';
    data[1] = data[0];

    // specify a subflow index using the third byte of the
    // 'flags' parameter from the 'send' call.
    int flags = select_subflow(0, 1);
    rc = send(acceptfd, data, 2, flags);
    DIE(rc < 0, "send");

    printf("Sent %c%c on subflow %d.\n", data[0], data[1], 1);

    // Wait for threshold number of subflows
    int threshold = 2;
    rc = setsockopt(acceptfd, IPPROTO_TCP, MPTCP_SET_SUB_EST_THRESHOLD, &threshold, sizeof(int));
    DIE(rc < 0, "setsockopt");

    int ret_threshold = 0;
    socklen_t ret_threshold_length = sizeof(ret_threshold);
    rc = getsockopt(acceptfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_THRESHOLD, &ret_threshold,
        &ret_threshold_length);
    DIE(rc < 0, "getsockopt");

    int count_before = 0;
    socklen_t count_before_length = sizeof(count_before);
    rc = getsockopt(acceptfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &count_before,
        &count_before_length);
    DIE(rc < 0, "getsockopt");

    printf("Set = %u, Get = %d, Count before = %d\n", threshold, ret_threshold, count_before);


    struct pollfd fds[1];
    memset(fds, 0, sizeof(struct pollfd));
    fds[0].fd = acceptfd;
    fds[0].events |= POLLCONN;

    poll(fds, 1, -1);

        int count_after = 0;
    socklen_t count_after_length = sizeof(count_after);
    rc = getsockopt(acceptfd, IPPROTO_TCP, MPTCP_GET_SUB_EST_COUNT, &count_after, &count_after_length);
    DIE(rc < 0, "getsockopt");
printf("Count after = %d\n", count_after);


    int index = 2;

    data[0] = 'N';
    data[1] = data[0];
    flags = select_subflow(0, index);
    rc = send(acceptfd, data, 2, flags);
    DIE(rc < 0, "send");
    printf("Sent %c%c on subflow %d.\n", data[0], data[1], index);

    close(acceptfd);
    close(listenfd);
}
