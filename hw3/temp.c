	// int iflag = 0;
	// int rflag = 0;
	// int sflag = 0;
	// char *ivalue = NULL;
	// char *rvalue = NULL;
	// char *svalue = NULL;
	// int index;
	// int c;

	// opterr = 0;

	// while ((c = getopt (argc, argv, ":ir:s:")) != -1)
	// 	switch (c)
	// 	{
	// 		case 'i':
	// 			iflag = 1;
	// 			if( !optarg && argv[optind] != NULL && '-' != argv[optind][0] ) 
	// 			{
	//           		ivalue = argv[optind++];
	// 			}
	// 			break;

	// 		case 'r':
	// 			rflag = 1;
	// 			rvalue = optarg;
	// 			break;

	// 		case 's':
	// 			sflag = 1;
	// 			svalue = optarg;
	// 			break;

	//       	case ':':       /* -f or -o without operand */
	// 			if (optopt == 's')
	// 				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	// 			else if (optopt == 'r')
	// 				fprintf (stderr, "Option -%c requires a file name.\n", optopt);
	// 			return 1;

	// 		case '?':
	// 			if (isprint (optopt))
	// 				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	// 			else
	// 				fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
	// 			return 1;
		
	// 		default:
	// 			print_app_usage();
	// 			abort ();
	// 	}

	// if (iflag && rflag)
	// {
	// 	puts("Cannot use the options -i and -r together");
	// 	return 1;
	// }

	// printf ("iflag = %d, ivalue = %s\n",
	// 	iflag, ivalue);

	// printf ("rflag = %d, rvalue = %s\n",
	// 	rflag, rvalue);  

	// printf ("sflag = %d, svalue = %s\n",
	// 	sflag, svalue);

	// // Concat all the non option argument
	// for (index = optind; index < argc; index++)
	// {
		
	// 	// printf ("Non-option argument %s\n", argv[index]);
	// 	if (argv[index] != NULL)
	// 	{
	// 		strcat(filter_exp, " ");
	// 		strcat(filter_exp, argv[index]);
	// 	}
		
	// }	





// char buf [SIZE] = {0};

	// /* code */
	// SSL_load_error_strings();
	// ERR_load_BIO_strings();
	// OpenSSL_add_all_algorithms();

	// BIO * bio;
	// bio = BIO_new_connect("127.0.0.1:8080");
	// if(bio == NULL)
	// {
	//     /* Handle the failure */
	// 	return -1;
	// }
	 
	// if(BIO_do_connect(bio) <= 0)
	// {
	//     /* Handle failed connection */
	// 	puts("Connection failed");
	// 	return -1;
	// }

	// puts("Successful connection");

	// // int x = BIO_read(bio, buf, len);
	// // if(x == 0)
	// // {
	// //     /* Handle closed connection */
	// // }
	// // else if(x < 0)
	// // {
	// //    if(! BIO_should_retry(bio))
	// //     {
	// //         /* Handle failed read here */
	// //     }
	 
	// //     /* Do something to handle the retry */
	// // }
	// gets(buf);

	// if(BIO_write(bio, buf, strlen(buf)) <= 0)
	// {
	//     if(! BIO_should_retry(bio))
	//     {
	//         /* Handle failed write here */
	//     	puts("Failed Write");
	//     	return -1;
	//     }
	 
	//     /* Do something to handle the retry */
	// }

	// puts("Successful write");

	// /* To reuse the connection, use this line */
 
	// // BIO_reset(bio);
 
	// /* To free it from memory, use this line */
 
	// BIO_free_all(bio);
