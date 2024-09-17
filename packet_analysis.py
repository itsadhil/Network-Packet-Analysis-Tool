import socket
import struct
import matplotlib.pyplot as plt

def analyze_packet(data):
    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    
    src_port = dest_port = None
    payload_data = data[iph_length:]
    
    if protocol == 6:  # TCP
        tcp_header = data[iph_length:iph_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        src_port = tcph[0]
        dest_port = tcph[1]
        data_offset = (tcph[4] >> 4) * 4
        payload_data = data[iph_length + data_offset:]
    
    elif protocol == 17:  # UDP
        udp_header = data[iph_length:iph_length+8]
        udph = struct.unpack('!HHHH', udp_header)
        src_port = udph[0]
        dest_port = udph[1]
        payload_data = data[iph_length + 8:]
    
    elif protocol == 1:  # ICMP
        icmp_header = data[iph_length:iph_length+4]
        icmph = struct.unpack('!BBH', icmp_header)
        icmp_type = icmph[0]
        icmp_code = icmph[1]
        icmp_checksum = icmph[2]
        payload_data = data[iph_length + 4:]
        src_port = dest_port = None
    
    return {
        "version": version,
        "header_length": iph_length,
        "ttl": ttl,
        "protocol": protocol,
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "icmp_type": icmp_type if protocol == 1 else None,
        "icmp_code": icmp_code if protocol == 1 else None,
        "icmp_checksum": icmp_checksum if protocol == 1 else None,
        "data": payload_data
    }

def plot_packet_statistics():
    try:
        with open("log.txt", "r") as log_file:
            logs = log_file.readlines()
            protocol_count = {"HTTP": 0, "HTTPS": 0}
            
            for log in logs:
                parts = log.split(" - ")
                if len(parts) == 2:
                    try:
                        packet_info = eval(parts[1].strip())
                        protocol = packet_info['protocol']
                        dest_port = packet_info.get('dest_port')
                        
                        # Count protocols by their protocol number
                        if protocol == 6:  # TCP
                            if dest_port == 80:
                                protocol_count["HTTP"] += 1
                            elif dest_port == 443:
                                protocol_count["HTTPS"] += 1
                            else:
                                protocol_count["TCP"] = protocol_count.get("TCP", 0) + 1
                        elif protocol == 17:  # UDP
                            protocol_count["UDP"] = protocol_count.get("UDP", 0) + 1
                        elif protocol == 1:  # ICMP
                            protocol_count["ICMP"] = protocol_count.get("ICMP", 0) + 1
                        elif protocol == 2:  # IGMP
                            protocol_count["IGMP"] = protocol_count.get("IGMP", 0) + 1
                        
                    except (SyntaxError, ValueError) as e:
                        print(f"Error parsing log entry: {e}")
            
            # Plot the statistics
            if protocol_count:
                protocols = list(protocol_count.keys())
                counts = list(protocol_count.values())
                
                plt.figure(figsize=(10, 6))
                plt.bar(protocols, counts, color='skyblue')
                plt.xlabel('Protocol')
                plt.ylabel('Number of Packets')
                plt.title('Packet Protocol Distribution')
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.tight_layout()
                plt.show()
                
            else:
                print("No packets logged to generate statistics.")
                
    except FileNotFoundError:
        print("No packets have been logged yet. Start sniffing first.")
