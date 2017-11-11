#define SIZE 1440
#define PROCESSED_BUFFER_SIZE 1456

struct relay_information {
    int from;
    int to;
    char *iv;
    const char *keyFileName;
    struct ctr_state *enc_dec_state;
};


void relay(int src, int dst, int encrypt_decrypt, char* iv, const char* keyFileName, struct ctr_state* enc_dec_state)
{

    int num_bytes_read, num_bytes_write = 0;
    char buffer[SIZE] = {0};
    // char inputBuffer[BUFFER_SIZE];
    char processedBuffer[PROCESSED_BUFFER_SIZE];

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
            int crypt_size;
            if (encrypt_decrypt == ENCRYPT) {
                crypt_size = encrypt(keyFileName, iv, enc_dec_state, buffer, num_bytes_read, processedBuffer);
            }
            else if (encrypt_decrypt == DECRYPT) {
                crypt_size = decrypt(keyFileName, iv, enc_dec_state, buffer, num_bytes_read, processedBuffer);
            }
                
            if (crypt_size < 0) {
                fprintf(stderr, "Problem with processing the input buffer.\n");
                // fflush(stdout);
                close(src);
                close(dst);
                return;
            }

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
