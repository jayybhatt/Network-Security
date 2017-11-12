

void* read_from_server(void* args)
{

    struct relay_information *relay_data;
    relay_data = (struct relay_information *) args;
    
    int from = relay_data->from;
    int to = relay_data->to;
    char *IV = relay_data->iv;
    const char *keyFileName = relay_data->keyFileName;
    struct ctr_state *dec_state = relay_data->enc_dec_state;
    relay(from, to, DECRYPT, IV, keyFileName, dec_state);
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
        fprintf(stderr, "\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    // initializing the IV and send it to the proxy-server
    // source to learn regarding AES CTR: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
    unsigned char  IV[AES_BLOCK_SIZE];
    if(!RAND_bytes(IV, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Cannot create random bytes for initializing the iv.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // SENDING THE IV TO THE PROXY-SERVER
    // source to learn: https://vcansimplify.wordpress.com/2013/03/14/c-socket-tutorial-echo-server/
    if (write(sock, IV, AES_BLOCK_SIZE) <= 0) {
        fprintf(stderr, "Cannot send the IV to the proxy-server side.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // initiating the encryption state for client
    struct ctr_state enc_state_client;
    init_ctr(&enc_state_client, IV);

    fprintf(stderr, "\n Successfully connected to server at - %s and process - %d\n", server_ip, server_port);

    struct relay_information *relay_data = (struct relay_information *) 
                                                malloc(sizeof(struct relay_information));
    relay_data->from = sock;
    relay_data->to = 1;
    relay_data->iv = IV;
    relay_data->keyFileName = keyFileName;
    relay_data->enc_dec_state = &enc_state_client;

    pthread_t read_from_server_thread;
    if( pthread_create( & read_from_server_thread , NULL , 
        read_from_server , (void*) relay_data) < 0) {
                printf("client:: Error::  creating read_from_server_thread failed.\n");
                fflush(stdout);
                close(sock);
                free(relay_data);
                return 0;
    }

    // CALL RELAY
    relay(0, sock, ENCRYPT, IV, keyFileName, &enc_state_client);

    return 0;
}
