#include <openssl/aes.h>
#include <openssl/rand.h>

#define ENCRYPT 1
#define DECRYPT 0

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};


// int bytes_read, bytes_written;
// unsigned char iv[AES_BLOCK_SIZE];
// struct ctr_state state;

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


int encrypt(const unsigned char* enc_key, char* p_txt, struct ctr_state * crypto_state, int length, char* c_txt)
{ 
        
    AES_KEY key;
    unsigned char indata[AES_BLOCK_SIZE];
	unsigned char outdata[AES_BLOCK_SIZE];
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }

	// init_ctr(&state, iv); //Counter call

	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
	// unsigned char* encrypted_data = (unsigned char*)malloc(sizeof(p_txt))	
	int num_bytes_read_total = 0, num_bytes_read = 0;

	while (num_bytes_read_total < length)
	{

		int remaining_bytes = (length - num_bytes_read_total);
		
		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
		bzero(indata, AES_BLOCK_SIZE);
		
		strncpy(indata, p_txt+num_bytes_read_total, num_bytes_read); 
		
		bzero(outdata, AES_BLOCK_SIZE);

		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
		strcat(c_txt, outdata);

		num_bytes_read_total += num_bytes_read;

	}

	// fprintf(stderr,"\nEncrypted  %s\n",c_txt);

	return num_bytes_read_total;
        // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
}

int decrypt(const unsigned char* dec_key, char* c_txt, struct ctr_state * crypto_state, int length, char* p_txt)
{ 
        
    AES_KEY key;
    unsigned char indata[AES_BLOCK_SIZE];
	unsigned char outdata[AES_BLOCK_SIZE];
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(dec_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }

	// init_ctr(&state, iv); //Counter call

	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
	// unsigned char* decrypted_data = (unsigned char*)malloc(sizeof(c_txt))	
	int num_bytes_read_total = 0, num_bytes_read = 0;

	while (num_bytes_read_total < length)
	{

		int remaining_bytes = (length - num_bytes_read_total);
		num_bytes_read = remaining_bytes < AES_BLOCK_SIZE?remaining_bytes:AES_BLOCK_SIZE;
		bzero(indata, AES_BLOCK_SIZE);

		strncpy(indata, c_txt+num_bytes_read_total, num_bytes_read); 
		
		bzero(outdata,AES_BLOCK_SIZE);
		AES_ctr128_encrypt(indata, outdata, num_bytes_read, &key, crypto_state->ivec, crypto_state->ecount, &(crypto_state->num));
        
		// bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
		strcat(p_txt, outdata);

		num_bytes_read_total += num_bytes_read;

	}
	// fprintf(stderr,"\nDecrypted  %s\n",p_txt);
	return num_bytes_read_total;
        // num_bytes_write = write(dst , crypto_text+num_bytes_write_total, crypt_size - num_bytes_write_total);
	
}
