
#define CONN_LIMIT 10

typedef struct connection_info{
    const char *ssh_ip;
    int ssh_port;
    int client_socket;
    const char *keyFile;
} connection_info;

void *read_from_client(void *args) {
    sock_stream_info *stream_data;
    stream_data = (sock_stream_info *) args;
    
    int src = stream_data->src;
    int dst = stream_data->dst;
    const char *keyFileName = stream_data->keyFileName;
    struct ctr_state *ctr_state = stream_data->ctr_state;

    sock_stream(src, dst, DECRYPT, keyFileName, ctr_state);
}

void *process_connection(void *args);

int server(int listen_on_port, const char* ssh_ip, int ssh_port, const char* keyFile)
{
    
    int server_fd, new_socket;
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
    fprintf(stderr, "\nBinding to port %d successful\n", listen_on_port);


    if (listen(server_fd, CONN_LIMIT) < 0)
    {
        fprintf(stderr, "\nListen on port %d failed\n", listen_on_port);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "\nWaiting for connections..\n");

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
            fprintf(stderr, "\nError in creating thread\n");
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
    const char *keyFileName = curr_conn->keyFile;

    struct hostent* host = NULL;

    char sshdIPAddress[16] = ""; // IPv4 can be at most 255.255.255.255 and last index for '\0'

    // MAKE A SOCKET AND CONNECT TO SSHD
    int sshdSocket = 0;
    if ((sshdSocket = socket(AF_INET , SOCK_STREAM , 0)) < 0)
    {
        fprintf(stderr, "\nError creating sshd socket\n");
        close(client_socket);
        free(args);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sshdServer;

    if ((host = gethostbyname(ssh_ip)) == 0)
    {
        fprintf(stderr, "\nHost not found\n");
        exit(EXIT_FAILURE);
    }

    sshdServer.sin_addr.s_addr = ((struct in_addr*) (host->h_addr))->s_addr;
    sshdServer.sin_family = AF_INET;
    sshdServer.sin_port = htons(ssh_port);
 
    if (connect(sshdSocket, (struct sockaddr *)&sshdServer, sizeof(sshdServer)) < 0)
    {
        fprintf(stderr, "\nError in connecting to sshd.\n");
        close(client_socket);
        free(args);
        exit(EXIT_FAILURE);
    }

    unsigned char  IV[AES_BLOCK_SIZE];
    int bytesReceived = read(client_socket, IV , AES_BLOCK_SIZE);
    if (bytesReceived != AES_BLOCK_SIZE) 
    { // AES_BLOCK_SIZE is 16
        fprintf(stderr, "\nError in receiving the IV.\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // initiating the decryption state for client
    struct ctr_state ctr_state;
    init_ctr(&ctr_state, IV);


    sock_stream_info *stream_data = (sock_stream_info *) malloc(sizeof(sock_stream_info));
    
    stream_data->src = client_socket;
    stream_data->dst = sshdSocket;
    stream_data->keyFileName = keyFileName;
    stream_data->ctr_state = &ctr_state;

    pthread_t read_from_client_thread;
    if( pthread_create( & read_from_client_thread , NULL , 
        read_from_client , (void*) stream_data) < 0) {
                fprintf(stderr, "\nError while creating thread.\n");
                close(client_socket);
                free(stream_data);
                exit(EXIT_FAILURE);
    }



    sock_stream(sshdSocket, client_socket, ENCRYPT, keyFileName, &ctr_state);

    close(client_socket);
    free(curr_conn);
    return 0; 

}
