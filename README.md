# Network Packet Analysis Tool

## Overview

This project is a Python-based network packet analysis tool that captures, logs, analyzes, and filters network packets. It provides functionalities to visualize packet data, filter specific packets based on various criteria, and generate statistics. The tool includes a GUI for managing network monitoring and detailed packet analysis.

## Components

### 1. **`packet_analysis.py`**

This script contains functions to analyze and visualize packet data.

#### Functions:
- **`analyze_packet(data)`**: Analyzes raw packet data, extracting details such as IP version, header length, TTL, protocol, source and destination IPs, ports, and ICMP fields.
- **`plot_packet_statistics()`**: Reads from a log file (`log.txt`), counts occurrences of different protocols, and plots a bar chart showing protocol distribution.

### 2. **`packet_filters.py`**

This script allows users to set and apply filters to the packets based on protocol, IP addresses, and destination ports.

#### Functions:
- **`filter_packet(packet)`**: Checks if a packet matches the allowed filters for protocols, IP addresses, and ports.
- **`set_filters()`**: Prompts the user to set allowed protocols, IP addresses, and destination ports for filtering.

### 3. **`packet_logging.py`**

This script provides functionality for logging packets, printing packet details, analyzing logged packets, and saving analyzed results.

#### Functions:
- **`log_packet(packet)`**: Appends packet details to a log file (`log.txt`) with a timestamp.
- **`print_packet(packet, detailed=False)`**: Prints packet details to the console. Can include detailed data based on the `detailed` flag.
- **`analyze_logged_packets()`**: Reads from the log file, filters packets based on user input, and displays or saves the filtered packets.
- **`reset_packet_data()`**: A placeholder function indicating that log reset functionality is disabled to prevent data loss.

## Usage

1. **Capture Packets**:
   - Use your packet sniffing code to capture packets and call `log_packet(packet)` to log each packet.

2. **Set Filters**:
   - Use `set_filters()` from `packet_filters.py` to define the criteria for filtering packets.

3. **Analyze Packets**:
   - Call `analyze_logged_packets()` from `packet_logging.py` to filter and analyze logged packets.

4. **Plot Statistics**:
   - Use `plot_packet_statistics()` from `packet_analysis.py` to visualize the distribution of different protocols based on logged data.

## Installation

Ensure you have the necessary Python modules installed. You can use the following command to install them:

```bash
pip install matplotlib
```

Run Main.py with cmd or any IDE with administrator Permissions

# Contribution

- Code By **Kamal** (https://github.com/darkness0308) (Discord: @mr_darkness_0308)
- Incorporation with Repo based on **Remote Network Monitor using Paramiko** 
