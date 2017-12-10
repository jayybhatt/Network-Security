import sys
import argparse
from scapy.all import *
from collections import deque

packet_q = deque(maxlen=10)

"""
Reference for parsing packets using scapy
	-	https://scapy.readthedocs.io/en/latest/usage.html
"""
def pkt_callback(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt.haslayer(DNSQR):
        if len(packet_q) > 0:
            for op in packet_q:
                if op[IP].dst == pkt[IP].dst and\
                op[IP].sport == pkt[IP].sport and\
                op[IP].dport == pkt[IP].dport and\
                op[DNSRR].rdata != pkt[DNSRR].rdata and\
                op[DNS].id == pkt[DNS].id and\
                op[DNS].qd.qname == pkt[DNS].qd.qname and\
                op[IP].payload != pkt[IP].payload:
                    print "\nDNS poisoning attempt detected"
                    print "TXID %s Request URL %s" % (
                        op[DNS].id, op[DNS].qd.qname.rstrip('.'))
                    print "Answer1 [%s]" % op[DNSRR].rdata
                    print "Answer2 [%s]" % pkt[DNSRR].rdata
        packet_q.append(pkt)


"""
reference for parsing CLI using argparse
    -   https://pymotw.com/2/argparse/
"""
def arg_parser():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="DNSDetect is a tool for detecting DNS poisoning attacks.")
    parser.add_argument(
        "-i",
        nargs="?",
        metavar="eth0",
        help="Name if the network interface to listen on.")
    parser.add_argument(
        "-r",
        nargs="?",
        metavar="tracefile.pcap",
        help="Name of a trace file in Tcpdump format.")
    parser.add_argument("expression", nargs="*", action="store")
    parser.add_argument(
        '-?', '-help', '--help', action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit()

    return args.i, args.r, args.expression


def main():
    interface, tracefile, bpf_filter = arg_parser()

    if tracefile:
        # hostnames = ''.join(hostnames)
        print "tracefile", tracefile

    if bpf_filter:
        bpf_filter = ' '.join(bpf_filter)
        print "bpf_filter", bpf_filter
    else:
        bpf_filter = "udp"

    if interface and tracefile:
        print "Cannot use interface (-i) and tracefile (-r) together"
        sys.exit()

    elif interface:
        # interface = args.i
        print interface
        sniff(iface=interface, prn=pkt_callback, filter=bpf_filter, store=0)
    elif tracefile:
        sniff(offline=tracefile, prn=pkt_callback, filter=bpf_filter, store=0)
    else:
        print "Choosing default interface"
        sniff(prn=pkt_callback, filter=bpf_filter, store=0)


if __name__ == '__main__':
    main()
