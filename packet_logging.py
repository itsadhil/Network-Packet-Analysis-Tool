from datetime import datetime

# Function to log packets, appending to existing log file
def log_packet(packet):
    with open("log.txt", "a") as log_file:  # Append mode to preserve older logs
        log_file.write(f"{datetime.now()} - {packet}\n")

# Function to print packet details
def print_packet(packet, detailed=False):
    print(f"[+] Time: {datetime.now()}")
    print(f"[+] Version: {packet['version']}")
    print(f"[+] Header Length: {packet['header_length']}")
    print(f"[+] TTL: {packet['ttl']}")
    print(f"[+] Protocol: {packet['protocol']}")
    print(f"[+] Source IP: {packet['source_ip']}")
    print(f"[+] Destination IP: {packet['destination_ip']}")
    if packet['src_port'] is not None and packet['dest_port'] is not None:
        print(f"[+] Source Port: {packet['src_port']}")
        print(f"[+] Destination Port: {packet['dest_port']}")
    if packet['protocol'] == 1:  # ICMP
        print(f"[+] ICMP Type: {packet['icmp_type']}")
        print(f"[+] ICMP Code: {packet['icmp_code']}")
        print(f"[+] ICMP Checksum: {packet['icmp_checksum']}")
    if detailed:
        print(f"[+] Data: {packet['data']}")
    print()

# Function to analyze and filter packets from log file
def analyze_logged_packets():
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
            
            # Filtering logic
            filter_choice = input("\nFilter by (P)rotocol, (I)P, (D)estination Port, or (N)one: ").lower()
            if filter_choice == 'p':
                proto = int(input("Enter protocol number to filter: "))
                filtered = [pkt for pkt in packets if pkt['protocol'] == proto]
            elif filter_choice == 'i':
                ip = input("Enter IP address to filter: ")
                filtered = [pkt for pkt in packets if pkt['source_ip'] == ip or pkt['destination_ip'] == ip]
            elif filter_choice == 'd':
                try:
                    port = int(input("Enter destination port number to filter: "))
                    filtered = [pkt for pkt in packets if pkt['dest_port'] == port]
                except ValueError:
                    print("Invalid port number. Please enter a valid integer.")
                    filtered = []
            else:
                filtered = packets
            
            # Display filtered packets
            if filtered:
                for pkt in filtered:
                    print_packet(pkt, detailed=True)
            else:
                print("No packets match the filter criteria.")
            
            # Option to save analyzed packets
            save_choice = input("Do you want to save the analyzed packets? (yes/no): ").lower()
            if save_choice in ['yes', 'y']:
                file_name = input("Enter the filename to save the packets (existing file will not be overwritten): ")
                try:
                    # Append new packets to the existing file
                    with open(file_name, "a") as save_file:
                        for pkt in filtered:
                            save_file.write(f"{datetime.now()} - {pkt}\n")
                    print(f"Packets appended to {file_name}.")
                except IOError as e:
                    print(f"Error saving file: {e}")
            else:
                print("Packets were not saved.")
                
    except FileNotFoundError:
        print("No packets have been logged yet. Start sniffing first.")

# Removed reset functionality to ensure logs aren't cleared
def reset_packet_data():
    print("Log reset functionality is disabled to prevent data loss.")
