
#define SIZE 1440
#define OUTPUT_SIZE 1456

#define ENCRYPT 1
#define DECRYPT 0

typedef struct {
    int src;
    int dst;
    const char *keyFileName;
    struct ctr_state *ctr_state;
} sock_stream_info ;


void print_app_usage()
{
    puts("pbproxy [-l port] -k keyfile destination port");
    puts("\n-l  Reverse-proxy mode: listen for inbound connections on <port> and relay");
    puts("them to <destination>:<port> ");
    puts("-k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)");

}


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


struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{

    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
    * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
 
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
 
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}


int encrypt(const unsigned char * enc_key, struct ctr_state * enc_state,
    char * plain_txt, int plain_txt_size , char * cipher_txt) {

    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        return -1;
    }
    
    int outBufCounter= 0;
    int num_bytes_read_total = 0;
    int num_bytes_read = 0;
    int i = 0;

    //Encrypting the data block by block
    while(num_bytes_read_total < plain_txt_size) {

        unsigned char indata[AES_BLOCK_SIZE];
        unsigned char outdata[AES_BLOCK_SIZE];

        num_bytes_read = 0;
        for (i = num_bytes_read_total; i < (num_bytes_read_total + AES_BLOCK_SIZE) && i < plain_txt_size; ++i) {
            indata[i - num_bytes_read_total] = plain_txt[i];
            num_bytes_read++;
        }

        AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
                
        strcpy(cipher_txt+outBufCounter, outdata);
        
        outBufCounter +=  num_bytes_read ;
        num_bytes_read_total += AES_BLOCK_SIZE;
    }       
    return outBufCounter ; 
}


int decrypt(const unsigned char * enc_key, struct ctr_state * dec_state,
    char * cipher_txt, int cipher_txt_size , char * plain_txt) {
    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        return -1;
    }
    

    int outBufCounter= 0;
    int num_bytes_read_total = 0;
    int num_bytes_read = 0;
    int i = 0;

    //Decrypting block by block 
    while(num_bytes_read_total < cipher_txt_size) {

        unsigned char indata[AES_BLOCK_SIZE];
        unsigned char outdata[AES_BLOCK_SIZE];

        num_bytes_read = 0;

        for (i = num_bytes_read_total; i < (num_bytes_read_total + AES_BLOCK_SIZE) && i < cipher_txt_size; ++i) {
            indata[i - num_bytes_read_total] = cipher_txt[i];
            num_bytes_read++;
        }

        AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        strcpy(plain_txt+outBufCounter, outdata);
        
        outBufCounter +=  num_bytes_read;
        num_bytes_read_total += AES_BLOCK_SIZE;
    }
    
    return outBufCounter;    
}


void sock_stream(int src, int dst, int encrypt_decrypt, const char* keyFileName, struct ctr_state* enc_dec_state)
{

    int num_bytes_read, num_bytes_write = 0;
    char indata[SIZE] = {0};
    char outdata[OUTPUT_SIZE] = {0};

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


