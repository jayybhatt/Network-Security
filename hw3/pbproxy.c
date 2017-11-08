#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <fcntl.h>
#define SIZE 1024

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
unsigned char* read_file(char* filename)
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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);

int main(int argc, char* argv[])
{
	int lflag = 0, kflag = 0, index = 0;
	unsigned int listen_on_port = 0;
	char c, *dest_ip = NULL;
	int dest_port = 0;

	char * key = NULL;
    char plaintext[SIZE] = {0};

    int valread;

	while ((c = getopt (argc, argv, ":l:k:h")) != -1)
	{

		switch (c)
		{
			case 'l':
				lflag = 1;
				listen_on_port = atoi(optarg);
				if (!listen_on_port)
				{
					fprintf (stderr, "Option -l requires a Port number.\n");
					print_app_usage();
					exit(1);
				}	

				break;

			case 'k':
				kflag = 1;
				if( optarg[0] == '-') 
				{
					printf("File not specified\n");
					print_app_usage();
					exit(1);
				}

				key = optarg;

				// key = read_file(optarg); 
				// if (!key)
				// {
				// 	printf("File Read Error - %s\n", optarg);
				// }
				
				break;

			case 'h':
				print_app_usage();
				exit(1);

	      	case ':':       // -f or -o without operand 
				if (optopt == 'k')
					fprintf (stderr, "Option -%c requires a Port Number.\n", optopt);
				else if (optopt == 'l')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
					
				print_app_usage();
				return 1;
		
			default:
				print_app_usage();
				exit(1);
		}
	}

	if  (key == NULL)
	{
		puts("Key Not specified");
		print_app_usage();
		exit(1);
	}

	// printf ("lflag = %d, listen_on_port = %d\n",
	// 	lflag, listen_on_port);

	// printf ("kflag = %d, key = %s\n",
	// 	kflag, key);  

	//check if there are enough arguments supplied to the program
	if (optind + 2 > argc)
	{
		printf("Not enough arguments \n");
		print_app_usage();
		exit(1);
	}

	dest_ip = argv[optind++];
	dest_port = atoi(argv[optind]);

	printf("dest_ip - %s\n", dest_ip);
	printf("dest_port - %d\n", dest_port);



/////////////////
	int sock2_fd;
    struct sockaddr_in sock2_serv_addr;
    int sock2_PORT = dest_port;
    int opt = 1;

    // Connecting to the actual server
    if ((sock2_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    memset(&sock2_serv_addr, '0', sizeof(sock2_serv_addr));
  
    sock2_serv_addr.sin_family = AF_INET;
    sock2_serv_addr.sin_port = htons(sock2_PORT);

    if(inet_pton(AF_INET, dest_ip, &sock2_serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
  
    if (connect(sock2_fd, (struct sockaddr *)&sock2_serv_addr, sizeof(sock2_serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    puts("Connected to server");

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

	int flags = fcntl(sock2_fd, F_GETFL);
	if (flags == -1) {
		printf("read sockfd flag error!\n");
		close(sock2_fd);
	}
	
	fcntl(sock2_fd, F_SETFL, flags | O_NONBLOCK);


    if (!lflag)
	{

		while(1)
	    {
	        bzero(plaintext , SIZE);
	        // gets(plaintext); // change to read from STDIN_FILENO
	        while ((valread = read(STDIN_FILENO, plaintext, SIZE)) > 0)
	        {
		        printf("Client typed - %s\n",plaintext );
		        write(sock2_fd , plaintext , strlen(plaintext));
		        printf("Sent to pbproxy-s - %s\n",plaintext );
	        	
	        }
	        
	        while((valread = read(sock2_fd, plaintext, SIZE)) > 0)
		   	{

		        // if (valread > 0)
		        // {
			        // printf("Received from Server - %s\n", plaintext);
			    write(STDOUT_FILENO, plaintext, SIZE);    
			        // send(new_socket , plaintext , strlen(plaintext) , 0 );
		        	// printf("Sent to Client - %s\n", plaintext);
		        	
		        // }
		   	}     
	    }
	}    
// /////////////////

    if (lflag)
    {

		int sock1_fd, new_socket;//, valread;
	    struct sockaddr_in sock1_serv_addr;
	    int addrlen = sizeof(sock1_serv_addr);
		
	    int sock1_PORT = listen_on_port;

	    // Listening on sock1_PORT for connections
	    // Creating socket file descriptor
	    if ((sock1_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	    {
	        perror("socket failed");
	        exit(EXIT_FAILURE);
	    }
	    

	    // Forcefully attaching socket to the port 8080
	    if (setsockopt(sock1_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
	                                                  &opt, sizeof(opt)))
	    {
	        perror("setsockopt");
	        exit(EXIT_FAILURE);
	    }

	    puts("Socket created for self");
	    sock1_serv_addr.sin_family = AF_INET;
	    sock1_serv_addr.sin_addr.s_addr = INADDR_ANY;
	    sock1_serv_addr.sin_port = htons( sock1_PORT );
	      
	    // Forcefully attaching socket to the port 8080
	    if (bind(sock1_fd, (struct sockaddr *)&sock1_serv_addr, sizeof(sock1_serv_addr))<0)
	    {
	        perror("bind failed");
	        exit(EXIT_FAILURE);
	    }
	    printf("Binding to port %d successful\n", sock1_PORT);

	    if (listen(sock1_fd, 3) < 0)
	    {
	        perror("listen");
	        exit(EXIT_FAILURE);
	    }
	    puts("waiting for connections");
	    
	    if ((new_socket = accept(sock1_fd, (struct sockaddr *)&sock1_serv_addr, 
	                       (socklen_t*)&addrlen))<0)
	    {
	        perror("accept");
	        exit(EXIT_FAILURE);
	    }

	    int flags = fcntl(sock1_fd, F_GETFL);
    	if (flags == -1) {
			printf("read sock 1 flag error!\n");
			printf("Closing connections and exit thread!\n");
			// close(sock);
			close(sock1_fd);
		}

		fcntl(sock1_fd, F_SETFL, flags | O_NONBLOCK);

	    while(1)
	    {
	        bzero(plaintext , SIZE);
	        while ((valread = read( new_socket , plaintext, SIZE)) > 0)
	        {

		    	// if (valread > 0)
		     //    {
			        printf("Received from Client - %s\n", plaintext);
			        write(sock2_fd , plaintext , strlen(plaintext));
		        	printf("Sent to Server- %s\n", plaintext);
		        	
		        // }
	        }

	        bzero(plaintext , SIZE);
	        while((valread = read( sock2_fd , plaintext, SIZE)) > 0)
	        {

		        // if (valread > 0)
		        // {
			        printf("Received from Server - %s\n", plaintext);
			        write(new_socket , plaintext , strlen(plaintext));
		        	printf("Sent to Client - %s\n", plaintext);
		        	
		        // }
	        }

		        
	    }
	
    }

    return 0;
	/* Set up the key and iv.
	*/

	/* A 256 bit key */
	// unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"0123456789012345";

	// /* Message to be encrypted */
	// unsigned char *plaintext =
	//             (unsigned char *)"This is a really huge assignment";
	//             //"The quick brown fox jumps over the lazy dog";

	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	* ciphertext which may be longer than the plaintext, dependant on the
	* algorithm and mode
	*/
	gets(plaintext);

	unsigned char ciphertext[128];

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];

	int decryptedtext_len, ciphertext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
	                        ciphertext);

	/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
	decryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;

}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;//handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;//handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return -1;//handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;//handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;//handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;//handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;//handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;//handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}