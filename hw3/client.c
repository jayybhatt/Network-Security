#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

// #define PORT 8080
#define SIZE 1024

int main(int argc, char const *argv[])
{
    struct sockaddr_in address;
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char hello[SIZE] = {0};
    const char* ip_addr = NULL;
    int PORT = 0;
    char buffer[SIZE] = {0};
    
    if (argc < 3)
    {
        puts("Usage : client  <server ip>  <server port>");
        return -1;
    }

    ip_addr = argv[1];
    PORT = atoi(argv[2]);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
      
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    while (1)
    {

        bzero(hello, SIZE);
        bzero(buffer, SIZE);
        // scanf("%s", hello);
        gets(hello);

        send(sock , hello , strlen(hello) , 0 );
        // printf("Hello message sent\n");
        // puts(hello);
        valread = read( sock , buffer, SIZE);
        if (valread > 0)
            printf("%s\n",buffer );
        
    }
    return 0;
}