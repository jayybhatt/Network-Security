
#define SIZE 1440
#define OUTPUT_SIZE 1456


void print_app_usage()
{
    puts("pbproxy [-l port] -k keyfile destination port");
    puts("\n-l  Reverse-proxy mode: listen for inbound connections on <port> and relay");
    puts("them to <destination>:<port> ");
    puts("-k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)");

}

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
    char indata[SIZE] = {0};
    char outdata[OUTPUT_SIZE] = {0};

    // bzero(indata, SIZE);

    // FIRST READING THE KEY FROM THE FILE
    unsigned char enc_key[16];
    strcpy(enc_key ,read_file(keyFileName));

    while (1)
    {

        num_bytes_read = read(src, indata, SIZE);
        if (num_bytes_read < 0)
        {
            fprintf(stderr, "\n Problem Reading\n");
            exit(EXIT_FAILURE);
        }

        else if (num_bytes_read == 0)
        {
            fprintf(stderr, "\n Connection Closed\n");
            return;
        }


        else
        {
            int crypt_size;
            if (encrypt_decrypt == ENCRYPT) {
                crypt_size = encrypt(enc_key, enc_dec_state, indata, num_bytes_read, outdata);
            }
            else if (encrypt_decrypt == DECRYPT) {
                crypt_size = decrypt(enc_key, enc_dec_state, indata, num_bytes_read, outdata);
            }
                
            if (crypt_size < 0) {
                fprintf(stderr, "Problem with processing the input indata.\n");
                close(src);
                close(dst);
                return;
            }

            int num_bytes_write_total = 0;

            while (num_bytes_write_total < num_bytes_read)
            {
                num_bytes_write = write(dst , indata+num_bytes_write_total, num_bytes_read - num_bytes_write_total);
                if (num_bytes_write <= 0)
                {
                    fprintf(stderr, "\nConnection Closed\n");
                    close(dst);
                    return;
                }
                num_bytes_write_total += num_bytes_write;
            }             
                
        }
   
    }
}
