import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import ipaddress
from tabulate import tabulate
from tqdm import tqdm
import csv
import json
import argparse
from colorama import Fore, Style, init
import logging
import sys

# Initialize colorama for colored terminal output
init(autoreset=True)

def setup_logging(logfile=None, verbose=False):
    log_level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if logfile:
        handlers.append(logging.FileHandler(logfile, mode='w'))
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def debug_print(msg, verbose):
    if verbose:
        logging.debug(msg)

def scan_batch(ip_batch, result_queue, timeout, verbose):
    try:
        debug_print(f"Scanning batch: {ip_batch}", verbose)
        # Create ARP request for multiple IPs at once
        arp_request = scapy.ARP(pdst=ip_batch)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send and receive packets
        answer = scapy.srp(packet, timeout=timeout, verbose=False)[0]

        clients = []
        for client in answer:
            client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
            try:
                hostname = socket.gethostbyaddr(client_info['IP'])[0]
                client_info['Hostname'] = hostname
            except socket.herror:
                client_info['Hostname'] = 'Unknown'
            clients.append(client_info)
            print(Fore.GREEN + f"[+] Found Host: {client_info['IP']} - {client_info['MAC']} - {client_info['Hostname']}")
            logging.info(f"Found Host: {client_info['IP']} - {client_info['MAC']} - {client_info['Hostname']}")
        if clients:
            result_queue.put(clients)
    except Exception as e:
        logging.error(f"Error scanning {ip_batch}: {e}")
        print(Fore.RED + f"[Error] Scanning {ip_batch}: {e}")

def print_result(result):
    if not result:
        print(Fore.YELLOW + "No active hosts found.")
        return
    table = [[client['IP'], client['MAC'], client['Hostname']] for client in result]
    print(tabulate(table, headers=["IP Address", "MAC Address", "Hostname"], tablefmt="grid"))

def export_to_csv(clients, filename="scan_results.csv"):
    with open(filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["IP", "MAC", "Hostname"])
        writer.writeheader()
        writer.writerows(clients)
    print(Fore.CYAN + f"[+] Results exported to {filename}")
    logging.info(f"Results exported to {filename}")

def export_to_json(clients, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(clients, f, indent=4)
    print(Fore.CYAN + f"[+] Results exported to {filename}")
    logging.info(f"Results exported to {filename}")

def export_results(clients, output_format):
    if output_format in ['csv', 'both']:
        export_to_csv(clients)
    if output_format in ['json', 'both']:
        export_to_json(clients)

def validate_cidr(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def chunker(seq, size):
    for pos in range(0, len(seq), size):
        yield seq[pos:pos + size]

def active_scan(cidr, timeout, workers, batch_size, verbose):
    results_queue = Queue()
    network = list(ipaddress.ip_network(cidr, strict=False).hosts())

    print(Fore.BLUE + f"[*] Starting active ARP scan on {cidr} with timeout={timeout}s, {workers} threads, batch size={batch_size}...")
    logging.info(f"Starting active ARP scan on {cidr} with timeout={timeout}s, {workers} threads, batch size={batch_size}")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        batches = list(chunker(network, batch_size))
        list(tqdm(executor.map(lambda ips: scan_batch([str(ip) for ip in ips], results_queue, timeout, verbose), batches), total=len(batches)))

    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())

    print_result(all_clients)
    logging.info(f"Scan complete: {len(all_clients)} active hosts found out of {len(network)} scanned IPs.")
    print(Fore.MAGENTA + f"\n[+] Scan Complete: {len(all_clients)} active hosts found out of {len(network)} scanned IPs.\n")
    return all_clients

def passive_sniff(timeout, verbose):
    print(Fore.BLUE + f"[*] Starting passive sniffing for {timeout} seconds...")
    logging.info(f"Starting passive sniffing for {timeout} seconds")
    packets = scapy.sniff(filter="arp", timeout=timeout)
    clients = []
    seen = set()
    for pkt in packets:
        if scapy.ARP in pkt and pkt[scapy.ARP].op == 2:  # ARP Reply
            ip = pkt[scapy.ARP].psrc
            mac = pkt[scapy.ARP].hwsrc
            if ip not in seen:
                seen.add(ip)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = 'Unknown'
                client_info = {'IP': ip, 'MAC': mac, 'Hostname': hostname}
                clients.append(client_info)
                print(Fore.GREEN + f"[+] Detected Host: {ip} - {mac} - {hostname}")
                logging.info(f"Detected Host: {ip} - {mac} - {hostname}")
    print_result(clients)
    logging.info(f"Passive sniffing complete: {len(clients)} hosts detected.")
    print(Fore.MAGENTA + f"\n[+] Passive sniffing complete: {len(clients)} hosts detected.\n")
    return clients

def main(network, timeout, workers, output_format, mode, passive_timeout, batch_size, verbose):
    if mode == 'active':
        clients = active_scan(network, timeout, workers, batch_size, verbose)
    else:
        clients = passive_sniff(passive_timeout, verbose)

    if clients:
        export_results(clients, output_format)
    else:
        print(Fore.YELLOW + "[!] No hosts found, nothing to export.")
        logging.info("No hosts found, nothing to export.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network ARP Scanner with Active and Passive Modes")
    parser.add_argument('-n', '--network', type=str, default=None, help='CIDR Network range to scan (active mode only)')
    parser.add_argument('-t', '--timeout', type=int, default=1, help='ARP request timeout in seconds (active mode only)')
    parser.add_argument('-w', '--workers', type=int, default=20, help='Number of concurrent threads (active mode only)')
    parser.add_argument('-b', '--batch-size', type=int, default=10, help='Batch size for IPs per thread (active mode only)')
    parser.add_argument('-o', '--output', type=str, choices=['csv', 'json', 'both'], default='both', help='Output format for results')
    parser.add_argument('-m', '--mode', type=str, choices=['active', 'passive'], default='active', help='Scan mode: active or passive')
    parser.add_argument('-p', '--passive-timeout', type=int, default=60, help='Passive sniffing duration in seconds (passive mode only)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('--logfile', type=str, default=None, help='Optional log file to save output')
    args = parser.parse_args()

    setup_logging(args.logfile, args.verbose)

    # Interactive prompt for network if not provided and mode is active
    if args.mode == 'active' and not args.network:
        while True:
            user_input = input("Enter the network range to scan (CIDR notation, e.g., 192.168.1.0/24): ").strip()
            if validate_cidr(user_input):
                args.network = user_input
                break
            else:
                print(Fore.RED + "Invalid CIDR notation. Please try again.")

    if args.mode == 'active' and not validate_cidr(args.network):
        print(Fore.RED + "Invalid CIDR notation.")
        sys.exit(1)

    try:
        main(args.network, args.timeout, args.workers, args.output, args.mode, args.passive_timeout, args.batch_size, args.verbose)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user.")
        logging.warning("Scan interrupted by user.")
        sys.exit(0)
