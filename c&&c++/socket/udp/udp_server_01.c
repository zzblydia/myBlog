// gcc -g udp_server.c -o bin_udp_server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define PORT 8995
#define BUFFER_SIZE 1024
#define SERVER_IP "10.10.10.10"

void print_timestamp() {
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    printf("[%s] ", buffer);
}

void print_hex(unsigned char *data, int len) {
    printf("Message length: 0x%02x (%d bytes)\n", len, len);
    printf("Message content (hex): ");
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    // 创建UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    server_addr.sin_port = htons(PORT);

    // 绑定socket到指定端口和IP
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("UDP server listening on %s:%d...\n", SERVER_IP, PORT);

    while (1) {
        // 接收UDP消息
        int recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0,
                              (struct sockaddr*)&client_addr, &addr_len);
        
        if (recv_len < 0) {
            perror("Receive failed");
            continue;
        }

        // 打印时间戳和客户端信息
        print_timestamp();
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        
        // 以十六进制打印消息
        print_hex((unsigned char*)buffer, recv_len);
    }

    close(sockfd);
    return 0;
}
