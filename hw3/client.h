#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

#define SIZE 1440

int client(const char* server_ip, int server_port, const char* keyFile)
{
    
    int sock = 0, num_bytes_read, num_bytes_write = 0;
    struct sockaddr_in serv_addr;
    struct hostent * host = NULL;

    // const char* server_ip = NULL;
    // int server_port = server_port;
    char buffer[SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  

    if ((host = gethostbyname(server_ip)) == 0)
    {
        fprintf(stderr, "\nHost not found\n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_addr.s_addr = ((struct in_addr*) (host->h_addr))->s_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);



    // CAN ADD THE FUNCTIONALITY TO SUPPORT HOSTNAME
      
    // Convert IPv4 and IPv6 addresses from text to binary form
    // if(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr)<=0) 
    // {
    //     fprintf(stderr, "\nInvalid address/ Address not supported \n");
    //     exit(EXIT_FAILURE);
    // }
  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        fprintf(stderr, "\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    int flags = fcntl(sock, F_GETFL);
    if (flags == -1) {
        printf("read sock flag error!\n");
        close(sock);
    }
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "\n $$ \n");

    fprintf(stderr, "\n Successfully connected to server at - %s and process - %d\n", server_ip, server_port);

    bzero(buffer, SIZE);
    while (1)
    {

        num_bytes_read = read(STDIN_FILENO, buffer, SIZE);
        if (num_bytes_read < 0)
        {
            fprintf(stderr, "\n Problem Reading\n");
            exit(EXIT_FAILURE);
        }

        else if (num_bytes_read == 0)
        {
            fprintf(stderr, "\n Connection Closed\n");
            exit(EXIT_FAILURE);
        }


        else// if (num_bytes_read > 0)
        {
            fprintf(stdout, "Client typed - %s\n",buffer );
            int num_bytes_write_total = 0;

            while (num_bytes_write_total < num_bytes_read)
            {
                
                num_bytes_write = write(sock , buffer+num_bytes_write_total, num_bytes_read - num_bytes_write_total);
                if (num_bytes_write <= 0)
                {
                    fprintf(stderr, "\nConnection Closed\n");
                    close(sock);

                    return 0;
                }
                fprintf(stdout, "Sent to pbproxy-s - %s\n",buffer );
                num_bytes_write_total += num_bytes_write;
            }             
                
        }

        // bzero(buffer, SIZE);
            
        while((num_bytes_read = read(sock, buffer, SIZE)) > 0)
        {

            fprintf(stdout, "Received from Server - %s\n", buffer);
            write(STDOUT_FILENO, buffer, SIZE);    
        }     
     
        // num_bytes_read = read(sock, buffer, SIZE);

        // if (num_bytes_read > 0)
            // printf("%s\n",buffer );
        
    }
    return 0;
}

/*
int sock2_fd;
    struct sockaddr_in sock2_serv_addr;
    int sock2_PORT = dest_port;
    int opt = 1;

    // Connecting to the actual server
    if ((sock2_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    memset(&sock2_serv_addr, '0', sizeof(sock2_serv_addr));
  
    sock2_serv_addr.sin_family = AF_INET;
    sock2_serv_addr.sin_port = htons(sock2_PORT);

    if(inet_pton(AF_INET, dest_ip, &sock2_serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if (connect(sock2_fd, (struct sockaddr *)&sock2_serv_addr, sizeof(sock2_serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    puts("Connected to server");

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    int flags = fcntl(sock2_fd, F_GETFL);
    if (flags == -1) {
        printf("read sockfd flag error!\n");
        close(sock2_fd);
    }
    
    fcntl(sock2_fd, F_SETFL, flags | O_NONBLOCK);


    if (!lflag)
    {

        while(1)
        {
            bzero(plaintext , SIZE);
            // gets(plaintext); // change to read from STDIN_FILENO
            while ((valread = read(STDIN_FILENO, plaintext, SIZE)) > 0)
            {
                printf("Client typed - %s\n",plaintext );
                write(sock2_fd , plaintext , strlen(plaintext));
                printf("Sent to pbproxy-s - %s\n",plaintext );
                
            }
            
            while((valread = read(sock2_fd, plaintext, SIZE)) > 0)
            {

                // if (valread > 0)
                // {
                    // printf("Received from Server - %s\n", plaintext);
                write(STDOUT_FILENO, plaintext, SIZE);    
                    // send(new_socket , plaintext , strlen(plaintext) , 0 );
                    // printf("Sent to Client - %s\n", plaintext);
                    
                // }
            }     
        }
    }    */