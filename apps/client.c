#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#define BUFFER_SIZE 4096

#define SERVER_PORT     1337
#define SERVER_IP       "127.0.0.1"
#define FILENAME        "recv_file"

void my_receive(int sockfd, char * buffer, int length) {
    int bytes_received = 0;
    int rc;
    while (bytes_received < length) {
        rc = recv(sockfd, buffer + bytes_received, length - bytes_received, 0);
        CHECK(rc >= 0, "recv");

        bytes_received += rc;
    }
}


int main(int argc, char* argv[]) {
    unsigned int server_port = SERVER_PORT;
    char *server_ip = SERVER_IP;
    char buffer[BUFFER_SIZE];
    char *filename = FILENAME;
    int ret;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:f:")) != -1) {
        switch (opt) {
            case 'i':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'f':
                filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage %s [-i SERVER_IP] [-p PORT] [-f RECV_FILENAME]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Open a TCP socket
    int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client_sockfd >= 0, "socket");

    // Setup sockaddr_in struct
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port);

    // Connect
	struct timeval begin, end;
	gettimeofday(&begin, NULL);
    ret = connect(client_sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    CHECK(ret >= 0, "connect");
	gettimeofday(&end, NULL);
	unsigned long long duration = 1000 * (end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec);
	printf("%12llu\n", duration);
    //printf("[client] Connected to %d\n", server_port);

    // Recv file size
    uint32_t file_size, file_size_net;
    my_receive(client_sockfd, (char*)&file_size_net, sizeof(file_size_net));
    file_size = ntohl(file_size_net);
    //printf("[client] Got file size: %u\n", file_size);

    // Open file
    int file_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(file_fd >= 0, "open");

    // Receive file
    int total = 0;
    while (total < file_size) {
        int bytes_recv = recv(client_sockfd, buffer, BUFFER_SIZE, 0);
        //printf("[client] Received %d bytes\n", (int)bytes_recv);
        write(file_fd, buffer, bytes_recv);
        total += bytes_recv;
    }

    close(file_fd);

    return 0;
}
