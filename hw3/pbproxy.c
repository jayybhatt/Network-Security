#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>	
#include <ctype.h>

#include "crypt.h"
#include "util.h"
#include "client.h"
#include "server.h"

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
					fprintf(stderr ,"File not specified\n");
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


/*
/////////////////
*/
	if (!lflag)
	{
		client(dest_ip, dest_port, key);
		exit(1);
	}
/*	
// /////////////////
*/
    if (lflag)
    {
    	server(listen_on_port, dest_ip, dest_port, key);
		exit(1);
	}

    return 0;
}