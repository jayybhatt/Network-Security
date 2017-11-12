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

#include "helper.h"
#include "client.h"
#include "server.h"

int main(int argc, char* argv[])
{
	int lflag = 0, kflag = 0;
	unsigned int listen_on_port = 0;
	char c, *dest_ip = NULL;
	int dest_port = 0;

	char * key = NULL;

	while ((c = getopt (argc, argv, ":l:k:")) != -1)
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
				
				break;

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

	//check if there are enough arguments supplied to the program
	if (optind + 2 > argc)
	{
		printf("Not enough arguments \n");
		print_app_usage();
		exit(1);
	}

	dest_ip = argv[optind++];
	dest_port = atoi(argv[optind]);

	printf("dest_host - %s\n", dest_ip);
	printf("dest_port - %d\n", dest_port);

	if (!lflag)
	{
		client(dest_ip, dest_port, key);
		exit(1);
	}

    if (lflag)
    {
    	server(listen_on_port, dest_ip, dest_port, key);
		exit(1);
	}

    return 0;
}