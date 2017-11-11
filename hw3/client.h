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
#define OUTPUT_SIZE 1456

struct relay_information {
    int from;
    int to;
    char *iv;
    const char *key_file_name;
    struct ctr_state *enc_dec_state;
};

/*
 * Reference:
 * http://stackoverflow.com/questions/174531/easiest-way-to-get-files-contents-in-c
 */
unsigned char* read_file(const char* filename)
{
    unsigned char *buffer = NULL;
    long length;
    FILE *f = fopen (filename, "rb");

    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
        {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }
    return buffer;
}

void relay(int src, int dst, int encrypt_decrpyt, const char* key_file_name, char* iv, struct ctr_state* crypto_state)
{

    int crypt_size = 0;
    int num_bytes_read, num_bytes_write = 0;
    char buffer[SIZE] = {0};
    char crypto_text[OUTPUT_SIZE] = {0};

    // FILE * key_file = fopen(key_file_name, "rb");
    // // read_file(key_file_name);
    
    // if(key_file == NULL) {
    //     fprintf(stderr, "Error opening the key_file.\n");
    //     exit(EXIT_FAILURE);
    // }
    
    unsigned char enc_key[16];
    strcpy(enc_key,read_file(key_file_name));
    // if(fread(enc_key, 1, AES_BLOCK_SIZE, key_file) != 16) {
    //     fprintf(stderr, "Error reading the key.\n");
    //     exit(EXIT_FAILURE);
    // }
    // fclose(key_file);


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
            bzero(crypto_text, OUTPUT_SIZE);
            if (encrypt_decrpyt)
            {
                // crypt_size = encrypt(key_file, crypto_state, buffer, num_bytes_read, crypto_text);
                crypt_size = encrypt(enc_key, buffer, crypto_state, num_bytes_read, crypto_text);
            
            }

            else
            {
                crypt_size = decrypt(enc_key, buffer, crypto_state, num_bytes_read,crypto_text);
            }


            if (num_bytes_read < 0) {
                fprintf(stderr, "\nProblem with processing the input buffer.\n");
                close(src);
                close(dst);
                return;
            }

            num_bytes_write_total = 0;
            while (num_bytes_write_total < crypt_size)
            {
                num_bytes_write = write(dst, crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
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
    char *iv = relay_data->iv;
    const char *key_file_name = relay_data->key_file_name;
    struct ctr_state *dec_state = relay_data->enc_dec_state;
    relay(from, to, DECRYPT, key_file_name, iv, dec_state);
}

int client(const char* server_ip, int server_port, const char* key_file_name)
{
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    struct hostent * host = NULL;

    char IV[AES_BLOCK_SIZE] = {};

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
  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        fprintf(stderr, "\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "\n Successfully connected to server at - %s and process - %d\n", server_ip, server_port);

    if(RAND_bytes(IV, AES_BLOCK_SIZE) <= 0)
    {
        fprintf(stderr, "\nCannot create random bytes for initializing the iv.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if(write(sock, IV, AES_BLOCK_SIZE) <= 0)
    {
        fprintf(stderr, "\nError sending IV to server\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    struct ctr_state dec_state_server;
    init_ctr(&dec_state_server, IV);

    struct ctr_state enc_state_client;
    init_ctr(&enc_state_client, IV);


    struct relay_information *relay_data = (struct relay_information *) 
                                                malloc(sizeof(struct relay_information));
    relay_data->from = sock;
    relay_data->to = 1;
    relay_data->iv = IV;
    relay_data->key_file_name = key_file_name;
    relay_data->enc_dec_state = &dec_state_server;

    pthread_t serverToSTDOUT_thread;
    if( pthread_create( & serverToSTDOUT_thread , NULL , 
        serverToSTDOUT , (void*) relay_data) < 0) {
                fprintf(stderr, "Creating serverToSTDOUT_thread failed.\n");
                fflush(stdout);
                close(sock);
                free(relay_data);
                return 0;
    }

    // CALL RELAY
    relay(0, sock, ENCRYPT, key_file_name, IV, &enc_state_client);


    return 0;
}
