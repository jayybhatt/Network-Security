

void* read_from_server(void* args)
{

    sock_stream_info *stream_data;
    stream_data = (sock_stream_info *) args;
    
    int src = stream_data->src;
    int dst = stream_data->dst;
    const char *keyFileName = stream_data->keyFileName;
    struct ctr_state *ctr_state = stream_data->ctr_state;
    sock_stream(src, dst, DECRYPT, keyFileName, ctr_state);
}

int client(const char* server_ip, int server_port, const char* keyFileName)
{
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    struct hostent * host = NULL;

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
  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        fprintf(stderr, "\nConnection Failed.\n");
        exit(EXIT_FAILURE);
    }

    // initializing the IV and send it to the proxy-server
    unsigned char  IV[AES_BLOCK_SIZE];
    if(!RAND_bytes(IV, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Error in creating IV.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // SENDING THE IV TO THE PROXY-SERVER
    if (write(sock, IV, AES_BLOCK_SIZE) <= 0) {
        fprintf(stderr, "Error in sending IV to the proxy-server side.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // initiating the encryption state for client
    struct ctr_state ctr_state;
    init_ctr(&ctr_state, IV);

    fprintf(stderr, "\n Successfully connected to server at - %s and process - %d\n", server_ip, server_port);

    sock_stream_info *stream_data = (sock_stream_info *) 
                                                malloc(sizeof(sock_stream_info));
    stream_data->src = sock;
    stream_data->dst = 1;
    stream_data->keyFileName = keyFileName;
    stream_data->ctr_state = &ctr_state;

    pthread_t read_from_server_thread;
    if( pthread_create( & read_from_server_thread , NULL , 
        read_from_server , (void*) stream_data) < 0) {
                fprintf(stderr, "\nError while creating thread.\n");
                close(sock);
                free(stream_data);
                return 0;
    }

    sock_stream(0, sock, ENCRYPT, keyFileName, &ctr_state);

    return 0;
}
