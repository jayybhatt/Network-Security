



// int encrypt(const unsigned char* enc_key, char* p_txt, struct ctr_state * crypto_state, int length, char* c_txt)
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
// 	// unsigned char* encrypted_data = (unsigned char*)malloc(sizeof(p_txt))	
// 	int num_bytes_read_total = 0, num_bytes_read = 0;

// 	while (num_bytes_read_total < length)
// 	{

// 		int remaining_bytes = (length - num_bytes_read_total);
		
// 		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
// 		bzero(indata, AES_BLOCK_SIZE);
		
// 		strncpy(indata, p_txt+num_bytes_read_total, num_bytes_read); 
		
// 		bzero(outdata, AES_BLOCK_SIZE);

// 		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
// 		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
// 		strcat(c_txt, outdata);

// 		num_bytes_read_total += num_bytes_read;

// 	}

// 	// fprintf(stderr,"\nEncrypted  %s\n",c_txt);

// 	return num_bytes_read_total;
//         // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
// }

// int decrypt(const unsigned char* dec_key, char* c_txt, struct ctr_state * crypto_state, int length, char* p_txt)
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
// 	// unsigned char* decrypted_data = (unsigned char*)malloc(sizeof(c_txt))	
// 	int num_bytes_read_total = 0, num_bytes_read = 0;

// 	while (num_bytes_read_total < length)
// 	{

// 		int remaining_bytes = (length - num_bytes_read_total);
// 		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
// 		bzero(indata, AES_BLOCK_SIZE);

// 		strncpy(indata, c_txt+num_bytes_read_total, num_bytes_read); 
		
// 		bzero(outdata,AES_BLOCK_SIZE);
// 		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
// 		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
// 		strcat(p_txt, outdata);

// 		num_bytes_read_total += num_bytes_read;

// 	}
// 	// fprintf(stderr,"\nDecrypted  %s\n",p_txt);
// 	return num_bytes_read_total;
//         // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
// }

#ifndef _ENCRYPTION
#define _ENCRYPTION


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
    int bytesRead = 0;
    int i;
    for (i = startFrom; i < (startFrom + AES_BLOCK_SIZE) && i < totalFromSize; ++i) {
        to[i - startFrom] = from[i];
        bytesRead++;
    }
    return bytesRead;
}

// int encrypt(const unsigned char* enc_key, char* p_txt, struct ctr_state * crypto_state, int length, char* c_txt)

// source to learn: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
int encrypt(const unsigned char * enc_key, struct ctr_state * enc_state,
	char * inputBuffer, int inputBufferSize , char * outputBuffer) {

    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        return -1;
    }
    
    int outBufCounter= 0;
    int bytesReadSoFar = 0;


    //Encrypting the data block by block
    while(bytesReadSoFar < inputBufferSize) {

        unsigned char AES_BLOCK_SIZE_Buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];

        int bytesRead = read_AES_BLOCK_SIZE(inputBuffer, AES_BLOCK_SIZE_Buffer,
            inputBufferSize, bytesReadSoFar);

        // AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
        AES_ctr128_encrypt(AES_BLOCK_SIZE_Buffer, ciphertext, bytesRead, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
        
        int i;
        for(i = 0; i < bytesRead ; i++ ) {
            outputBuffer[outBufCounter + i] = ciphertext[i];
        }
        
        outBufCounter +=  bytesRead ;
        bytesReadSoFar += AES_BLOCK_SIZE;
    }       
    return outBufCounter ; 
}


int decrypt(const unsigned char * enc_key, struct ctr_state * dec_state,
	char * inputBuffer, int inputBufferSize , char * outputBuffer) {
    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        return -1;
    }
    

    int outBufCounter= 0;
    int bytesReadSoFar = 0;

    //Decrypting block by block 
    while(bytesReadSoFar < inputBufferSize) {

        unsigned char AES_BLOCK_SIZE_Buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];

        int bytesRead = read_AES_BLOCK_SIZE(inputBuffer, ciphertext,
            inputBufferSize, bytesReadSoFar);

        
        AES_ctr128_encrypt(ciphertext, AES_BLOCK_SIZE_Buffer, bytesRead, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        int i;
        for(i = 0; i < bytesRead ; i++ ) {
            outputBuffer[outBufCounter + i] = AES_BLOCK_SIZE_Buffer[i];
        }
        
        outBufCounter +=  bytesRead;
        bytesReadSoFar += AES_BLOCK_SIZE;
    }
    
    return outBufCounter ;    
}

#endif