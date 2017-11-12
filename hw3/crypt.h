



// int encrypt(const unsigned char* enc_key, char* plain_txt, struct ctr_state * crypto_state, int length, char* cipher_txt)
// { 
        
//     AES_KEY key;
//     unsigned char indata[AES_BLOCK_SIZE];
// 	unsigned char outdata[AES_BLOCK_SIZE];
// 	//Initializing the encryption KEY
// 	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
//     {
//         fprintf(stderr, "Could not set encryption key.");
//         exit(1); 
//     }

// 	// init_ctr(&state, iv); //Counter call

// 	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
// 	// unsigned char* encrypted_data = (unsigned char*)malloc(sizeof(plain_txt))	
// 	int num_bytes_read_total = 0, num_bytes_read = 0;

// 	while (num_bytes_read_total < length)
// 	{

// 		int remaining_bytes = (length - num_bytes_read_total);
		
// 		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
// 		bzero(indata, AES_BLOCK_SIZE);
		
// 		strncpy(indata, plain_txt+num_bytes_read_total, num_bytes_read); 
		
// 		bzero(outdata, AES_BLOCK_SIZE);

// 		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
// 		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
// 		strcat(cipher_txt, outdata);

// 		num_bytes_read_total += num_bytes_read;

// 	}

// 	// fprintf(stderr,"\nEncrypted  %s\n",cipher_txt);

// 	return num_bytes_read_total;
//         // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
// }

// int decrypt(const unsigned char* dec_key, char* cipher_txt, struct ctr_state * crypto_state, int length, char* plain_txt)
// { 
        
//     AES_KEY key;
//     unsigned char indata[AES_BLOCK_SIZE];
// 	unsigned char outdata[AES_BLOCK_SIZE];
// 	//Initializing the encryption KEY
// 	if (AES_set_encrypt_key(dec_key, 128, &key) < 0)
//     {
//         fprintf(stderr, "Could not set encryption key.");
//         exit(1); 
//     }

// 	// init_ctr(&state, iv); //Counter call

// 	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
// 	// unsigned char* decrypted_data = (unsigned char*)malloc(sizeof(cipher_txt))	
// 	int num_bytes_read_total = 0, num_bytes_read = 0;

// 	while (num_bytes_read_total < length)
// 	{

// 		int remaining_bytes = (length - num_bytes_read_total);
// 		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
// 		bzero(indata, AES_BLOCK_SIZE);

// 		strncpy(indata, cipher_txt+num_bytes_read_total, num_bytes_read); 
		
// 		bzero(outdata,AES_BLOCK_SIZE);
// 		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
// 		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
// 		strcat(plain_txt, outdata);

// 		num_bytes_read_total += num_bytes_read;

// 	}
// 	// fprintf(stderr,"\nDecrypted  %s\n",plain_txt);
// 	return num_bytes_read_total;
//         // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
// }

#define ENCRYPT 1
#define DECRYPT 0

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

int read_AES_BLOCK_SIZE(char *from, char *to, int totalFromSize, int startFrom) {
    int num_bytes_read = 0;
    int i;
    for (i = startFrom; i < (startFrom + AES_BLOCK_SIZE) && i < totalFromSize; ++i) {
        to[i - startFrom] = from[i];
        num_bytes_read++;
    }
    return num_bytes_read;
}

// int encrypt(const unsigned char* enc_key, char* plain_txt, struct ctr_state * crypto_state, int length, char* cipher_txt)

// source to learn: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
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


    //Encrypting the data block by block
    while(num_bytes_read_total < plain_txt_size) {

        unsigned char indata[AES_BLOCK_SIZE];
        unsigned char outdata[AES_BLOCK_SIZE];

        int num_bytes_read = read_AES_BLOCK_SIZE(plain_txt, indata, plain_txt_size, num_bytes_read_total);

        // AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
        AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
        
        int i;
        for(i = 0; i < num_bytes_read ; i++ ) {
            cipher_txt[outBufCounter + i] = outdata[i];
        }
        
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

    //Decrypting block by block 
    while(num_bytes_read_total < cipher_txt_size) {

        unsigned char outdata[AES_BLOCK_SIZE];
        unsigned char indata[AES_BLOCK_SIZE];

        int num_bytes_read = read_AES_BLOCK_SIZE(cipher_txt, indata, cipher_txt_size, num_bytes_read_total);

        
        AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        int i;
        for(i = 0; i < num_bytes_read ; i++ ) {
            plain_txt[outBufCounter + i] = outdata[i];
        }
        
        outBufCounter +=  num_bytes_read;
        num_bytes_read_total += AES_BLOCK_SIZE;
    }
    
    return outBufCounter;    
}
