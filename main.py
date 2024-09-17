import socket
import time
from packet_analysis import analyze_packet, plot_packet_statistics
from packet_filters import filter_packet, set_filters
from packet_logging import log_packet, print_packet, analyze_logged_packets, reset_packet_data
import os
import matplotlib.pyplot as plt
from collections import defaultdict, deque

# Global variables for tracking bandwidth by IP
ip_bandwidth = defaultdict(int)  # Store bandwidth usage by IP
time_series = defaultdict(lambda: deque(maxlen=100))  # Store time series data

def update_bandwidth(ip, packet_size):
    """Update the bandwidth usage for the given IP."""
    global ip_bandwidth
    ip_bandwidth[ip] += packet_size

def plot_bandwidth_graph():
    """Plot bandwidth usage by IP in real-time as a line graph."""
    plt.ion()  # Turn on interactive mode
    fig, ax = plt.subplots(figsize=(10, 6))
    
    while True:
        ax.clear()
        current_time = time.time()
        
        for ip, bandwidth in ip_bandwidth.items():
            time_series[ip].append((current_time, bandwidth))
            times, values = zip(*time_series[ip])
            ax.plot(times, values, label=f'IP: {ip}')
        
        ax.set_xlabel('Time(s)')
        ax.set_ylabel('Packets Per Second (bytes)')
        ax.set_title('Real-time Bandwidth Usage by IP')
        ax.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.pause(1)  # Pause to update the graph


def print_boxed(text):
    # Determine the width of the box based on the length of the text
    width = max(len(line) for line in text.split('\n')) + 4
    
    # Print the top border
    print('+' + '-' * (width - 2) + '+')
    
    # Print the text lines with side borders
    for line in text.split('\n'):
        print(f'| {line.ljust(width - 3)} |')
    
    # Print the bottom border
    print('+' + '-' * (width - 2) + '+')

def clear_log_file():
    log_file_path = "log.txt"
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
    open(log_file_path, "w").close()

import threading  # Import threading to run the graph in parallel

def start_sniffer():
    # Clear the log file before starting a new session
    clear_log_file()
    
    # Start the bandwidth monitoring graph in a separate thread
    graph_thread = threading.Thread(target=plot_bandwidth_graph)
    graph_thread.daemon = True  # Daemon thread will close when the main program exits
    graph_thread.start()
    
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    print("[*] Sniffer started... Press Ctrl+C to stop.")
    
    # Initialize statistics counters
    packet_count = 0
    protocol_count = {}
    ip_count = {}
    port_count = {}
    
    # Record the start time
    start_time = time.time()
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            packet = analyze_packet(raw_data)
            if filter_packet(packet):
                log_packet(packet)
                print_packet(packet, detailed=False)
                
                # Update statistics
                packet_count += 1
                protocol = packet['protocol']
                protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
                
                # Update IP address statistics
                src_ip = packet['source_ip']
                dest_ip = packet['destination_ip']
                ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
                ip_count[dest_ip] = ip_count.get(dest_ip, 0) + 1
                
                # Update bandwidth usage
                packet_size = len(raw_data)
                update_bandwidth(src_ip, packet_size)
                update_bandwidth(dest_ip, packet_size)
                
                # Update port statistics for UDP and TCP
                if protocol in [6, 17]:  # TCP or UDP
                    src_port = packet['src_port']
                    dest_port = packet['dest_port']
                    if src_port is not None:
                        port_count[src_port] = port_count.get(src_port, 0) + 1
                    if dest_port is not None:
                        port_count[dest_port] = port_count.get(dest_port, 0) + 1
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffer.")
    finally:
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()
        
        # Record the end time
        end_time = time.time()
        
        # Calculate the duration
        duration = end_time - start_time
        
        # Print the detailed report
        report = []
        report.append("Detailed Report:")
        report.append(f"Total Packets Captured: {packet_count}")
        report.append(f"Total Time Taken: {duration:.1f} s")
        
        # Protocol breakdown
        report.append("\nProtocol Breakdown:")
        for protocol, count in protocol_count.items():
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Unknown ({protocol})")
            report.append(f"Protocol {protocol_name}: {count} packets")
            
            # Detailed breakdown for TCP and UDP
            if protocol in [6, 17]:  # TCP or UDP
                report.append(f"  Ports:")
                sorted_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)
                for port, count in sorted_ports:
                    report.append(f"    Port {port}: {count} packets")
        
        # IP address breakdown
        report.append("\nIP Address Breakdown:")
        sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            report.append(f"IP Address {ip}: {count} packets")
        
        # Print the formatted report
        print_boxed("\n".join(report))
        
        if input("\nDo you want to generate a graph of the packet statistics? (yes/no): ").lower() in ['yes', 'y']:
            plot_packet_statistics()


def generate_full_report():
    try:
        with open("log.txt", "r") as log_file:
            logs = log_file.readlines()
            packets = []
            for log in logs:
                parts = log.split(" - ")
                if len(parts) == 2:
                    try:
                        packet_info = eval(parts[1].strip())
                        packets.append(packet_info)
                    except (SyntaxError, ValueError) as e:
                        print(f"Error parsing log entry: {e}")
                else:
                    print(f"Invalid log entry format: {log.strip()}")
            
            # Initialize statistics counters
            protocol_count = {}
            ip_count = {}
            port_count = {}
            
            # Analyze packets
            for packet in packets:
                protocol = packet['protocol']
                protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
                
                # Update IP address statistics
                src_ip = packet['source_ip']
                dest_ip = packet['destination_ip']
                ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
                ip_count[dest_ip] = ip_count.get(dest_ip, 0) + 1
                
                # Update port statistics for UDP and TCP
                if protocol in [6, 17]:  # TCP or UDP
                    src_port = packet['src_port']
                    dest_port = packet['dest_port']
                    if src_port is not None:
                        port_count[src_port] = port_count.get(src_port, 0) + 1
                    if dest_port is not None:
                        port_count[dest_port] = port_count.get(dest_port, 0) + 1
            
            # Print the detailed report
            report = []
            report.append("Full Analyzed Report:")
            report.append(f"Total Packets Analyzed: {len(packets)}")
            
            # Protocol breakdown
            report.append("\nProtocol Breakdown:")
            for protocol, count in protocol_count.items():
                protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Unknown")
                report.append(f"Protocol {protocol_name} ({protocol}): {count} packets")
                
                # Detailed breakdown for TCP and UDP
                if protocol in [6, 17]:
                    report.append(f"  Ports:")
                    sorted_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)
                    for port, count in sorted_ports:
                        report.append(f"    Port {port}: {count} packets")
            
            # IP address breakdown
            report.append("\nIP Address Breakdown:")
            sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips:
                report.append(f"IP Address {ip}: {count} packets")
            
            # Print the formatted report
            print_boxed("\n".join(report))
            
    except FileNotFoundError:
        print("No packets have been logged yet. Start sniffing first.")

def main():
    actions = {
        '1': start_sniffer,
        '2': analyze_logged_packets,
        '3': set_filters,
        '4': plot_packet_statistics,
        '5': generate_full_report,
        '0': exit
    }
    
    while True:
        print("\nPacket Sniffer CLI")
        print("1. Start Sniffer")
        print("2. Analyze Logged Packets")
        print("3. Set Filters")
        print("4. Generate Packet Statistics Graph")
        print("5. Generate Full Analyzed Report")
        print("0. Exit")
        choice = input("Choose an option: ")
        
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

