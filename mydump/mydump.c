#include <stdio.h>
#include <stdlib.h>
#include "headers.h"
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

char* print_payload(const u_char *payload, int len);

char* print_hex_ascii_line(const u_char *payload, int len);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_usage()
{

	puts("\n\n");

	printf("Usage: mydump [ -i <interface>]    [-r <file>]    [ -s <string>]    <expression> \n");
	puts("\n\t\t [-s \"<string>\"][include in quotes if given multiple words]");
	printf("\n");
	printf("Options:\n");

	puts("\t\t-i  Live capture from the network device <interface> (e.g., eth0).\n");

	puts("\t\t-r  Read packets from <file> in tcpdump format.\n");

	puts("\t\t-s  Keep only packets that contain <string> in their payload (after any BPF filter is applied).");
	
	puts("\t\t<expression> is a BPF filter that specifies which packets will be dumped."); 
	puts("\t\t    If no filter is given, all packets seen on the interface (or contained in the trace) will be dumped.");
	puts("\t\t    Otherwise, only packets matching <expression> will be dumped.\n");

	printf("\n");

	return;
}

int main(int argc, char *argv[])
{

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[100];	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	char *string_filter = NULL;
	int packet_num_to_read = -1;

	int iflag = 0;
	int rflag = 0;
	int sflag = 0;
	char *ivalue = NULL;
	char *rvalue = NULL;
	char *svalue = NULL;
	int index;
	int c;

	opterr = 0;

	while ((c = getopt (argc, argv, ":ir:s:")) != -1)
		switch (c)
		{
			case 'i':
				iflag = 1;
				if( !optarg && argv[optind] != NULL && '-' != argv[optind][0] ) 
				{
	          		ivalue = argv[optind++];
				}
				break;

			case 'r':
				rflag = 1;
				rvalue = optarg;
				break;

			case 's':
				sflag = 1;
				svalue = optarg;
				break;

	      	case ':':       /* -f or -o without operand */
				if (optopt == 's')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'r')
					fprintf (stderr, "Option -%c requires a file name.\n", optopt);
				return 1;

			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
		
			default:
				print_app_usage();
				abort ();
		}

	if (iflag && rflag)
	{
		puts("Cannot use the options -i and -r together");
		return 1;
	}

	printf ("iflag = %d, ivalue = %s\n",
		iflag, ivalue);

	printf ("rflag = %d, rvalue = %s\n",
		rflag, rvalue);  

	printf ("sflag = %d, svalue = %s\n",
		sflag, svalue);

	// Concat all the non option argument
	for (index = optind; index < argc; index++)
	{
		
		// printf ("Non-option argument %s\n", argv[index]);
		if (argv[index] != NULL)
		{
			strcat(filter_exp, " ");
			strcat(filter_exp, argv[index]);
		}
		
	}	

	printf("Filter expression is %s\n", filter_exp);

  //Check whether the filename exists
	if (rflag)
	{
		FILE *file = NULL;
		if (file = fopen(rvalue, "r"))
		{
			fclose(file);
	    	handle = pcap_open_offline(rvalue, errbuf);
			if (handle == NULL) {
				printf("pcap_open_offline() failed: %s\n", errbuf);
				return 1;
			}
			goto apply_filter;

	    	return 0;
		}
		else
		{
			printf("\n File \"%s\" does not exists\n", rvalue);
			return 2;
		}
		
	}

	if (svalue != NULL)
		string_filter = svalue;

	if (ivalue != NULL)
		dev = ivalue;

	else{
		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	apply_filter:
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		print_app_usage();
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* Grab a packet */
	pcap_loop(handle, packet_num_to_read, got_packet, (u_char*)svalue);

	/* And close the session */
	pcap_close(handle);
	return(0);

}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
char*
print_hex_ascii_line(const u_char *payload, int len)
{
	int i;
	int gap;
	const u_char *ch;
	char * result = (char *)malloc(sizeof(char)*400);
	char tmp[200];
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		sprintf( tmp, "%02x ", *ch);
		strcat(result, tmp);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			strcat(result, " ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		strcat(result, " ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			strcat(result, "   ");
		}
	}
	strcat(result, "   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
		{
			sprintf( tmp, "%c", *ch);
			strcat(result, tmp);
			
		}
		else
			strcat(result, ".");
		ch++;
	}

	strcat(result, "\n");

return result;
}

/*
 * print packet payload data (avoid printing binary data)
 */
char*
print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	// int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;
	char * result = (char *)malloc(sizeof(char)*1400);
	char * tmp = NULL;

	if (len <= 0)
		return NULL;

	/* data fits on one line */
	if (len <= line_width) {
		return print_hex_ascii_line(ch, len);
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;

		/* print line */
		tmp = print_hex_ascii_line(ch, line_len);
		strcat(result, tmp);

		/* compute total remaining */
		len_rem = len_rem - line_len;

		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;

		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			tmp = print_hex_ascii_line(ch, len_rem);
			strcat(result, tmp);
			break;
		}
	}

return result;
}

char* u_char_to_str(const u_char *MAC)
{
	static char str[18];

    if(MAC == NULL) return "";

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", 
             MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

    return str;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet)
{
	time_t packet_time;
	struct tm *time_stamp;
	char time[64], buf[64];
	char* result = (char *)malloc(sizeof(char)*(400));
	char* payload_str = (char *)malloc(sizeof(char)*(1400));
	char tmp[200];
	char *s = (char *)args;

	if (s == NULL)
		s = "";

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;			/* The UDP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	packet_time = header->ts.tv_sec;
	time_stamp = localtime(&packet_time);

	strftime(time, sizeof time, "%Y-%m-%d %H:%M:%S", time_stamp);
	sprintf(result, "\n%s.%06ld ", time, header->ts.tv_usec);

	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	sprintf(tmp, "%s -> %s ", u_char_to_str(ethernet->ether_shost), u_char_to_str(ethernet->ether_dhost));
	strcat(result, tmp);
	
	sprintf(tmp, "type 0x%03x ", ntohs(ethernet->ether_type));
	strcat(result, tmp);
	
	sprintf(tmp, "len %d\n", header->caplen);
	strcat(result, tmp);

    if (ntohs (ethernet->ether_type) == 0x0806)
    {
    	strcat(result, "ARP\n");
    	payload = (u_char *)(packet + SIZE_ETHERNET);
    	size_payload = (header->caplen - SIZE_ETHERNET);
    	goto print_payload;
    }

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	char * proto = NULL;
	/* determine protocol */	
	switch(ip->ip_p) {

		case IPPROTO_TCP:
			proto = "TCP";
			/* define/compute tcp header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			sprintf(tmp, "%s:%d -> %s:%d %s\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport), proto);
			
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			break;

		case IPPROTO_UDP:
			proto = "UDP";
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			size_udp = SIZE_ETHERNET;
			sprintf(tmp, "%s:%d -> %s:%d %s\n", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport), proto);
			
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			break;

		case IPPROTO_ICMP:
			strcat(result, "ICMP");
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_ICMP);
			goto print_payload;

		default:

			break;	
	}
	
	strcat(result, tmp);
		
	print_payload:

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {

		payload_str = print_payload(payload, size_payload);

		if (s != NULL || s != "")
		{

			char * p = strstr(payload_str, s);
			if (p != NULL)
			{
				printf("%s\n", result);
				printf("%s\n", payload_str);
			}
		}
		else
		{
			printf("%s\n", result);
			printf("%s\n", payload_str);
		}

		free(result);
	}
	
	return;
}