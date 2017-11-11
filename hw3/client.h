#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>

#define SIZE 1440

struct relay_information {
    int from;
    int to;
    // char *iv;
    // char *keyFileName;
    // struct ctr_state *enc_dec_state;
};


void relay(int src, int dst)
{

    int num_bytes_read, num_bytes_write = 0;
    char buffer[SIZE] = {0};

    // bzero(buffer, SIZE);

    while (1)
    {

        num_bytes_read = read(src, buffer, SIZE);
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


        else
        {
            // fprintf(stderr, "Client typed - %s\n",buffer );
            int num_bytes_write_total = 0;

            while (num_bytes_write_total < num_bytes_read)
            {
                num_bytes_write = write(dst , buffer+num_bytes_write_total, num_bytes_read - num_bytes_write_total);
                if (num_bytes_write <= 0)
                {
                    fprintf(stderr, "\nConnection Closed\n");
                    close(dst);

                    return;
                }
                // fprintf(stderr, "Sent to pbproxy-s - %s\n",buffer );
                num_bytes_write_total += num_bytes_write;
            }             
                
        }
   
    }
}

void* serverToSTDOUT(void* args)
{

    struct relay_information *relay_data;
    relay_data = (struct relay_information *) args;
    
    int from = relay_data->from;
    int to = relay_data->to;
    // char *iv_server = relay_data->iv;
    // char *keyFileName = relay_data->keyFileName;
    // struct ctr_state *dec_state = relay_data->enc_dec_state;
    relay(from, to);//, DECRYPT, iv_server, keyFileName, dec_state);
}

int client(const char* server_ip, int server_port, const char* keyFile)
{
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    struct hostent * host = NULL;

    // const char* server_ip = NULL;
    // int server_port = server_port;

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

    // fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    // int flags = fcntl(sock, F_GETFL);
    // if (flags == -1) {
    //     printf("read sock flag error!\n");
    //     close(sock);
    // }
    // fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "\n $$ \n");

    fprintf(stderr, "\n Successfully connected to server at - %s and process - %d\n", server_ip, server_port);



    struct relay_information *relay_data = (struct relay_information *) 
                                                malloc(sizeof(struct relay_information));
    relay_data->from = sock;
    relay_data->to = 1;
    // relay_data->iv = iv_server;
    // relay_data->keyFileName = keyFileName;
    // relay_data->enc_dec_state = &dec_state_server;

    pthread_t serverToSTDOUT_thread;
    if( pthread_create( & serverToSTDOUT_thread , NULL , 
        serverToSTDOUT , (void*) relay_data) < 0) {
                printf("client:: Error::  creating serverToSTDOUT_thread failed.\n");
                fflush(stdout);
                close(sock);
                free(relay_data);
                return 0;
    }

    // CALL RELAY
    relay(0, sock);


    return 0;
}
