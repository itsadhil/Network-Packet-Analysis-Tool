ALLOWED_PROTOCOLS = []
ALLOWED_IPS = []
ALLOWED_PORTS = []

def filter_packet(packet):
    if ALLOWED_PROTOCOLS and packet['protocol'] not in ALLOWED_PROTOCOLS:
        return False
    if ALLOWED_IPS and packet['source_ip'] not in ALLOWED_IPS and packet['destination_ip'] not in ALLOWED_IPS:
        return False
    if ALLOWED_PORTS and packet['dest_port'] not in ALLOWED_PORTS:
        return False
    return True

def set_filters():
    global ALLOWED_PROTOCOLS, ALLOWED_IPS, ALLOWED_PORTS
    protocol_input = input("Enter protocols to filter (comma separated, e.g., 1,6,17) or leave blank to allow all: ")
    if protocol_input:
        ALLOWED_PROTOCOLS = [int(p) for p in protocol_input.split(',')]
    ip_input = input("Enter IPs to filter (comma separated) or leave blank to allow all: ")
    if ip_input:
        ALLOWED_IPS = ip_input.split(',')
    port_input = input("Enter ports to filter (comma separated, e.g., 80,443) or leave blank to allow all: ")
    if port_input:
        ALLOWED_PORTS = [int(p) for p in port_input.split(',')]
