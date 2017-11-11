#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>


#define MAX_CLIENTS 10


typedef struct connection_info{
    const char *ssh_ip;
    int ssh_port;
    int client_socket;
    const char *keyFile;
} connection_info;

void *clientToSshd(void *args) {
    struct relay_information *relay_data;
    relay_data = (struct relay_information *) args;
    
    int from = relay_data->from;
    int to = relay_data->to;
    char *iv = relay_data->iv;
    const char *key_file_name = relay_data->key_file_name;
    struct ctr_state *dec_state = relay_data->enc_dec_state;

    relay(from, to, DECRYPT, key_file_name, iv, dec_state);
}



void *process_connection(void *args);

int server(int listen_on_port, const char* ssh_ip, int ssh_port, const char* keyFile)
{
    
    int server_fd, new_socket, num_bytes_read;
    struct sockaddr_in server_addr;
    int opt = 1;
    int addrlen = sizeof(server_addr);
      
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        fprintf(stderr, "\nSocket creation failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        fprintf(stderr, "\nSetsockopt error\n");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons( listen_on_port );
      
    // Attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&server_addr, 
                                 sizeof(server_addr))<0)
    {
        fprintf(stderr, "\nBind failed\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Binding to port %d successful\n", listen_on_port);


    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        fprintf(stderr, "\nListen on port %d failed\n", listen_on_port);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "waiting for connections");

    while (new_socket = accept(server_fd, (struct sockaddr *)&server_addr, 
                       (socklen_t*)&addrlen))
    {
        fprintf(stderr, "\nClient connected with socket - %d\n", new_socket);

        pthread_t conn_process_thread;
        
        connection_info* main_conn = (connection_info*)malloc(sizeof(connection_info));
        main_conn->client_socket = new_socket;
        main_conn->ssh_ip = ssh_ip;
        main_conn->ssh_port = ssh_port;
        main_conn->keyFile = keyFile;

        if (pthread_create(&conn_process_thread, NULL, process_connection, main_conn) < 0)
        {
            fprintf(stderr, "\nThread creation error\n");
            close(server_fd);
            exit(EXIT_FAILURE);
        }


    }

    if (new_socket < 0)
    {
        fprintf(stderr, "\nConnection accept error\n");
        exit(EXIT_FAILURE);
    }

    close(server_fd);

    
    return 0;
}


void *process_connection(void *args)
{
    
    connection_info *curr_conn = (connection_info*) args;

    int client_socket = curr_conn->client_socket;    
    const char* ssh_ip = curr_conn->ssh_ip;
    int ssh_port = curr_conn->ssh_port;
    const char *key_file_name = curr_conn->keyFile;

    struct hostent* host = NULL;

    char buffer[1024] = {0};
    int num_bytes_read = 0;

    char sshdIPAddress[16] = ""; // IPv4 can be at most 255.255.255.255 and last index for '\0'

    char IV[AES_BLOCK_SIZE] = {};
    
    // MAKE A SOCKET AND CONNECT TO SSHD
    int sshdSocket = 0;
    sshdSocket = socket(AF_INET , SOCK_STREAM , 0);

    if (sshdSocket == -1) {
        fprintf(stderr, "\nCan't make socket connection to sshd server\n");
        close(client_socket);
        free(args);
        exit(EXIT_FAILURE);
    }

    // CONNECTING TO THE REMOTE SSHD SERVER
    struct sockaddr_in sshdServer;

    if ((host = gethostbyname(ssh_ip)) == 0)
    {
        fprintf(stderr, "\nHost not found\n");
        exit(EXIT_FAILURE);
    }

    sshdServer.sin_addr.s_addr = ((struct in_addr*) (host->h_addr))->s_addr;
    sshdServer.sin_family = AF_INET;
    sshdServer.sin_port = htons(ssh_port);
 
    //CONNECT TO REMOTE SSHD
    if (connect(sshdSocket, (struct sockaddr *)&sshdServer, sizeof(sshdServer)) < 0)
    {
        fprintf(stderr, "\nCouldn't connect to the sshd through the created socket\n");
        close(client_socket);
        free(args);
        exit(EXIT_FAILURE);
    }

    // RECEIVING THE IV_CLIENT
    num_bytes_read = read(client_socket, IV , AES_BLOCK_SIZE);
    if (num_bytes_read != AES_BLOCK_SIZE) { // AES_BLOCK_SIZE is 16
        fprintf(stderr, "Error in receiving the IV of the proxy-client side.\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }


    struct ctr_state enc_state_server;
    init_ctr(&enc_state_server, IV);

    // initiating the decryption state for client
    struct ctr_state dec_state_client;
    init_ctr(&dec_state_client, IV);

    fprintf(stderr, "\n%s\n", IV);

    struct relay_information *relay_data = (struct relay_information *) malloc(sizeof(struct relay_information));
    
    relay_data->from = client_socket;
    relay_data->to = sshdSocket;
    relay_data->iv = IV;
    relay_data->key_file_name = key_file_name;
    relay_data->enc_dec_state = &dec_state_client;
    bzero(buffer , SIZE);

    // RELAYING ALL THE DATA FROM CLIENT TO SSHD + DECRYPTION
    pthread_t clientToSshd_thread;
    if( pthread_create( & clientToSshd_thread , NULL , 
        clientToSshd , (void*) relay_data) < 0) {
                printf("server:: Error::  creating clientToSshd_thread failed.\n");
                fflush(stdout);
                close(client_socket);
                free(relay_data);
                exit(EXIT_FAILURE);
    }

    relay(sshdSocket,  client_socket, ENCRYPT, key_file_name, IV, &enc_state_server);
    
    close(client_socket);
    free(curr_conn);
    exit(EXIT_FAILURE);

}
