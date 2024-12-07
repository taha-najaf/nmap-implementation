from scapy.all import IP, ICMP, sr1
from scapy.all import IP, ICMP, sr1, get_if_hwaddr, conf
import socket
import argparse
import time
import struct
import random
import select
from scapy.all import IP, ICMP, sr1, conf

# Constants for ICMP
ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp') #usually 1
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by users or processes with administrator rights.'
}


def checksum(source_string):
    """Calculate checksum for ICMP packet."""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count += 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff) #carry
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00) #big indian
    return answer


def create_packet(id):
    """Create a new ICMP echo request packet."""
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = 192 * 'Q'
    my_checksum = checksum(header + data.encode())
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                         socket.htons(my_checksum), id, 1)
    return header + data.encode()


def do_one(dest_addr, timeout=1):
    """Send one ping to the given address with raw socket."""
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error as e:
        if e.errno in ERROR_DESCR:
            print(ERROR_DESCR[e.errno])
            return None
        raise
    try:
        host = socket.gethostbyname(dest_addr)   #convert to ip
    except socket.gaierror:
        print(f"Host {dest_addr} could not be resolved.")
        return None

    packet_id = int((id(timeout) * random.random()) % 65535)
    packet = create_packet(packet_id)
    my_socket.sendto(packet, (host, 1))

    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


def receive_ping(my_socket, packet_id, time_sent, timeout):
    """Receive ping from the socket."""
    time_left = timeout
    while True:
        start_time = time.time()
        readable = select.select([my_socket], [], [], time_left) #wait for data
        if not readable[0]:
            return None
        time_received = time.time()
        received_packet, _ = my_socket.recvfrom(1024)
        icmp_header = received_packet[20:28]
        type, code, _, packet_id_recv, _ = struct.unpack("bbHHh", icmp_header)
        if packet_id_recv == packet_id:
            return time_received - time_sent
        time_left -= time_received - start_time
        if time_left <= 0:
            return None


def traceroute(host, max_hops=30, timeout=2):
    """Perform a traceroute to the specified host using ICMP echo requests."""
    try:
        dest_addr = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Host {host} could not be resolved.")
        return

    print(f"Traceroute to {host} ({dest_addr}), {max_hops} hops max:")
    print(f"{'Hop':<5}{'IP Address':<20}{'Hostname':<30}{'RTT (ms)':<15}{'ICMP Type':<15}")

    for ttl in range(1, max_hops + 1):
        # Send ICMP packet with increasing TTL
        pkt = IP(dst=dest_addr, ttl=ttl) / ICMP()

        # Send packet and wait for a response
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            # No response within the timeout
            print(f"{ttl:<5}{'*':<20}{'*':<30}{'*':<15}{'Request timed out.'}")
        else:
            # Successful reply
            round_trip_time = (reply.time - pkt.sent_time) * \
                1000  # Time in milliseconds

            # Attempt to resolve hostname
            try:
                hostname = socket.gethostbyaddr(reply.src)[0]
            except socket.herror:
                hostname = "N/A"

            # Get the ICMP type of the reply
            icmp_type = reply[ICMP].type
            icmp_type_desc = "Echo Reply" if icmp_type == 0 else "Time Exceeded" if icmp_type == 11 else "Other"

            print(
                f"{ttl:<5}{reply.src:<20}{hostname:<30}{round_trip_time:<15.2f}{icmp_type_desc:<15}")

            # Stop if the destination was reached
            if reply.src == dest_addr:
                print("Reached the destination.")
                break
            


def check_host_with_icmp(host):
    """Check if a host is reachable using ICMP ping."""
    response_time = do_one(host, timeout=2)
    if response_time is not None:
        print(
            f"{host} is reachable with ICMP (ping). Response time: {response_time:.4f} seconds.")
        return True
    else:
        print(f"{host} is not reachable with ICMP (ping).")
        return False


def check_host_status(host, port=80):
    """Check if a host is online by attempting to connect to a specified port by tcp."""
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"{host} is online.")
            return True
    except (socket.timeout, socket.error):
        print(f"{host} is offline")
        return False


def scan_ports(host, start_port, end_port):
    """Scan a range of ports on the specified host to check if they are open."""
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.create_connection((host, port), timeout=1):
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"

                hostname = socket.gethostbyaddr(
                    host)[0] if host.replace(".", "").isdigit() else host

                print(f"Open port detected: {host} -- Port: {port}")
                print(f"-- Service: {service}")
                print(f"-- Hostname: {hostname}")

                open_ports.append(port)
        except (socket.timeout, socket.error):
            continue
    return open_ports


def measure_port_latency(host, port, attempts=5):
    """Measure the average TCP connection latency to a specific port on a host with high precision."""
    total_time = 0
    successful_attempts = 0

    for _ in range(attempts):
        try:
            # Start timing with high precision
            start_time = time.perf_counter()

            # Create a socket and attempt a connection to the specific port
            with socket.create_connection((host, port), timeout=2):
                end_time = time.perf_counter()

            # Calculate the round-trip time for the connection
            delay = end_time - start_time
            total_time += delay
            successful_attempts += 1

        except (socket.timeout, socket.error):
            # If the connection fails or times out, skip to the next attempt
            print(f"Connection to {host} failed or timed out.")
            continue

        # Optional: pause briefly between attempts to avoid rapid-fire requests
        time.sleep(1)

    if successful_attempts > 0:
        # Calculate and display the average latency
        average_latency = total_time / successful_attempts
        print(f"Average TCP connection latency to {host} is {average_latency:.4f} seconds.")
    else:
        print(f"Could not measure TCP connection latency to {host}:{port}.")



def dns_lookup(host):
    """Perform DNS and reverse DNS lookups."""
    try:
        ip_address = socket.gethostbyname(host)
        print(f"IP Address of {host}: {ip_address}")

        # Perform reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        print(f"Reverse DNS for {ip_address}: {hostname}")
    except socket.gaierror:
        print(f"DNS lookup failed for {host}.")
    except socket.herror:
        print(f"Reverse DNS lookup failed for IP address {ip_address}.")


def interactive_requests():
    """Prompt for GET or POST input and send the corresponding request using raw sockets."""
    host = 'localhost'
    port = 8000

    while True:
        try:
            command = input(
                "Enter 'GET user_id' or 'POST user_name user_age' to simulate a request: ").strip()

            with socket.create_connection((host, port)) as client_socket:
                if command.lower().startswith("get"):
                    _, user_id = command.split()
                    request = f"GET /{user_id} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    client_socket.sendall(request.encode())

                elif command.lower().startswith("post"):
                    _, user_name, user_age = command.split()
                    request = f"POST {user_name} {user_age} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    client_socket.sendall(request.encode())

                else:
                    print(
                        "Invalid command. Please enter 'GET user_id' or 'POST user_name user_age'.")
                    continue

                # Receive the server response
                response = client_socket.recv(4096).decode()
                print(f"Response from the server:\n{response}")

        except KeyboardInterrupt:
            print("\nExiting interactive mode.")
            break
        except Exception as e:
            print(f"Error: {e}")


def display_usage():
    """Display custom usage structure similar to nmap."""
    usage_text = """
Usage:
    python nmap.py [host] [options]

Options:
    -p, --ports     <range>   Range of ports to scan (e.g., 20-80)
    -l, --latency   <port>    measure_port_latency for a specific port (provide port number)
    -a, --attempts  <count>   Number of attempts to measure_port_latency (default: 5)
    -d, --dns                 Perform DNS and reverse DNS lookups for the host
    -i, --interactive         Enter interactive mode for GET and POST requests
    -c, --icmp                Check host reachability using ICMP (ping)
    -t, --traceroute          Perform a traceroute to the host
    
Examples:
    python nmap.py 192.168.1.1 -p 20-80
    python nmap.py example.com -l 80 -a 10
    python nmap.py example.com -d
    python nmap.py example.com -c
    python nmap.py example.com -t
    python nmap.py -i
"""
    print(usage_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check if a host is online, scan ports, measure_port_latency, perform DNS lookup, and handle GET/POST requests.",
        add_help=False)
    parser.add_argument("host", type=str, nargs="?",
                        help="Host to check (IP address or hostname)")
    parser.add_argument("-p", "--ports", type=str,
                        help="Range of ports to scan (e.g., 20-80)")
    parser.add_argument("-l", "--latency", type=int,
                        help="measure_port_latency for a specific port (provide port number)")
    parser.add_argument("-a", "--attempts", type=int, default=5,
                        help="Number of attempts to measure_port_latency (default: 5)")
    parser.add_argument("-d", "--dns", action="store_true",
                        help="Perform DNS and reverse DNS lookups for the host")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Enter interactive mode for GET and POST requests")
    parser.add_argument("-c", "--icmp", action="store_true",
                        help="Check host reachability using ICMP (ping)")
    parser.add_argument("-t", "--traceroute", action="store_true",
                        help="Perform a traceroute to the host")
    parser.add_argument("-h", "--help", action="store_true",
                        help="Show this help message and exit")

    args = parser.parse_args()

    if args.help:
        display_usage()
        sys.exit()

    if args.interactive:
        interactive_requests()
        sys.exit()

    if args.host:
        if args.traceroute:
            traceroute(args.host)
        elif args.icmp:
            check_host_with_icmp(args.host)
        else:
            if check_host_status(args.host):
                if args.ports:
                    try:
                        start_port, end_port = map(int, args.ports.split('-'))
                        scan_ports(args.host, start_port, end_port)
                    except ValueError:
                        print(
                            "[ERROR] Invalid port range. Use format: start-end (e.g., 20-80).")

                if args.latency:
                    measure_port_latency(args.host, args.latency, args.attempts)


                if args.dns:
                    dns_lookup(args.host)
