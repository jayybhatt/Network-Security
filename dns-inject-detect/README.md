## Report

1. Commands to execute:

-	dnsinject
	-
	```
	dnsinject [-i interface] [-h hostnames] expression
	
		-i  Listen on network device <interface> (e.g., eth0). If not specified,
			dnsinject should select a default interface to listen on. The same
			interface should be used for packet injection.

		-h  Read a list of IP address and hostname pairs specifying the hostnames to
			be hijacked. If '-h' is not specified, dnsinject should forge replies for
			all observed requests with the local machine's IP address as an answer.
		
		<expression> is a BPF filter that specifies a subset of the traffic to be
		monitored. This option is useful for targeting a single or a set of particular
		victims.
	```

	Example
	
	```
	dnsinject.py -h hostnames.txt udp port 53
	```
	
	This command is used to run the dnsinject python script on all the domain names 
	mentioned in the hostnames.txt file and with a bpf filter on the packets, to
	sniff only the packets with UDP as Transport layer protocol and port number 53 
	[code description below]

-	dnsdetect
	-
	```
	dnsdetect [-i interface] [-r tracefile] expression

	-i  Listen on network device <interface> (e.g., eth0). If not specified,
		the program should select a default interface to listen on.

	-r  Read packets from <tracefile> (tcpdump format). Useful for detecting
		DNS poisoning attacks in existing network traces.

	<expression> same as in dnsinject.
	```

	Example
	
	```
	dnsdetect.py -r hw4.pcap
	```

	This command will start the python script to detect the DNS poisoning attempts, such as
	the one's made by dnsinject.py. In this case, the script will be reading in offline mode
	from the provided hw4.pcap Capture file.
	

2. Decription of programs:

-	dnsinject
	-	This code sniff the network in promiscuous mode, on the specified interface. [default if not specified]
	-	Then is checks to see if the hostnames file is provided or not.
	-	If given, then it defines a global hostnames dictionary, 
			where key is the hostname and value is the IP to be spoofed.
	-	Before starting to capture packets, the local machine IP address is recorded at run time by the code.	
	-	Whenever a packet is captured, it is checked for the presence of DNS layer. If present, it checks if
			the packet is a DNS query or DNS response. As we only want to capture DNS query and then send spoofed packet 
			to the victim that generated the query.
	-	For each captured DNS query, it collects the DNS domain name that is being queried.
	-	Then it checks if hostnames dictionary is defined.
		-	If not, then the local machine IP is chosen as the DNS response. [Ans to the DNS query] 
		-	If yes, it checks if the domain name is present in the dictionary. 
		-	If the domain name is present, then the corresponding IP address value is chosen as the DNS response.
		-	If the domain name is absent from the dictionary, don't attack. 
	-	The spoofed packet response is made as follows, 
			src ip = dst ip in DNS query packet
			dst ip = src ip in DNS query packet
			Similarly for the UDP ports.
			DNS id and query is copied from the DNS query packet
			qr flag is set to 1, suggesting it is a DNS reply
			aa flag is set to 1, suggesting the reply is from authoritative server
			resource record is made using the domain name, ttl and the spoofed ip.

-	dnsdetect
	-	This code sniffs the network in the same way as the above code.
	-	It checks if the tracefile is given, if so then it will start the sniffing in offline mode.
	-	It also checks that interface and tracefile should not be given together.
	-	To detect a DNS poisoning attempt, the following logic is used.
		-	Store the last 10 DNS responses captured.
		-	Whenever a new DNS response is captured, check in the past 10 files [one by one], to see if, 
		-	dst ip address of both are same
		-	src and dst port numbers are same
		-	DNS id is same
		-	DNS query record is same
		-	DNS reply is different
	-	If the above conditions are met, then there is a DNS poisoning attempt, therefore alert by printing the output.
	-	The false positives are considered, with the following assumptions, 
		-	In case of DNS round robin load balancing, the legitimate consecutive responses,
				may arrive at a certain time interval. If it is a moderate size LAN, then there is a high chance
				of the second legitimate response arriving at a gap of 10 or more packets. Hence, the first 
				response won't be there to compare, and the second response will not be marked as attack, 
				unless there is an actual poisoning attempt.
		-	Also, it is assumed that the consecutive responses will have different TXID. This is the case when,
				the first query response was a server that was down. Then the client will make another query
				with different TXID for the same domain name.

	-	OUTPUT of dnsdetect for the tracefile with successful poisoning attacks 
			generated using the dnsinject tool
			
			jay@jayz-phoenix:~/Documents/MS/Network-Security/hw4$ sudo python dnsdetect.py -r hw4.pcap

			tracefile hw4.pcap

			DNS poisoning attempt detected
			TXID 59185 Request URL www.reddit.com
			Answer1 [192.168.66.6]
			Answer2 [reddit.map.fastly.net.]

			DNS poisoning attempt detected
			TXID 59185 Request URL www.reddit.com
			Answer1 [192.168.66.6]
			Answer2 [reddit.map.fastly.net.]

			DNS poisoning attempt detected
			TXID 60648 Request URL foo.example.com
			Answer1 [10.6.6.6]
			Answer2 [snsdnsicannorgnoc�1x:�� u]

			DNS poisoning attempt detected
			TXID 60648 Request URL foo.example.com
			Answer1 [10.6.6.6]
			Answer2 [snsdnsicannorgnoc�1x:�� u]

			DNS poisoning attempt detected
			TXID 18183 Request URL www.cs.stonybrook.edu
			Answer1 [192.168.66.6]
			Answer2 [ec2-107-22-178-157.compute-1.amazonaws.com.]

			DNS poisoning attempt detected
			TXID 18183 Request URL www.cs.stonybrook.edu
			Answer1 [192.168.66.6]
			Answer2 [ec2-107-22-178-157.compute-1.amazonaws.com.]


3.	Test Environment for both the codes
	-	Linux 4.10.0-42-generic x86_64
	-	Distributor ID:	Ubuntu
		Description:	Ubuntu 16.04.3 LTS
		Release:	16.04
		Codename:	xenial

	- 	Python 2.7.12 (default, Nov 20 2017, 18:23:56) 
		[GCC 5.4.0 20160609] on linux2



4.	Issues
	-	BPF filter does not work with scapy in the offline mode.


5.	References
	-	https://pymotw.com/2/argparse/
	-	https://scapy.readthedocs.io/en/latest/usage.html



