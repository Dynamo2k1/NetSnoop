
# NetSnoop - Ultimate Packet Sniffer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)  
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/Status-Active-success)]()  
[![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

## Overview

**NetSnoop** is an advanced, feature-rich packet sniffer written in Python that captures and decodes live network traffic. Designed to mimic Wireshark, it supports multiple protocols including IPv4, ARP, IPv6, TCP, UDP, ICMP, DNS, DHCP, and VLAN. NetSnoop also offers real-time protocol statistics, hex dump output, and the ability to save packets in PCAP format for later analysis.

**Key Features:**
- **Multi-Protocol Support:** Captures and decodes IPv4, ARP, IPv6, TCP, UDP, ICMP, DNS, DHCP, and VLAN tagged frames.
- **Real-Time Statistics:** Displays live counts of captured packets by protocol at configurable intervals.
- **PCAP File Saving:** Optionally save captured packets to a PCAP file for later analysis in tools like Wireshark.
- **Hex Dump Display:** View detailed hex dumps of each packet.
- **Filtering:** Display only packets of a specified protocol using a simple filter.
- **Promiscuous Mode:** Automatically sets the network interface to promiscuous mode.
- **Colorful Output:** Professional, colorized, and timestamped output for improved readability.
- **Advanced Features:** Basic HTTP cleartext detection on TCP payloads, DHCP tagging, DNS tagging, and VLAN support.

## Installation

### Prerequisites
- **Python 3.8+**  
- **Linux OS** (NetSnoop uses AF_PACKET raw sockets and is Linux-specific.)  
- **Root Privileges** (Run with `sudo`.)

### Setup

Clone the repository:

```bash
git clone https://github.com/Dynamo2k1/NetSnoop.git
cd NetSnoop
```

Install any required dependencies (if applicable):

```bash
pip install -r requirements.txt
```

*(Note: If no external packages are needed, you can skip this step.)*

## Usage

Run NetSnoop with root privileges. For example:

```bash
sudo python3 NetSnoop.py -i eth1 -o capture.pcap --dump --stats-interval 30 --filter IPv4
```

### Command-Line Options

| Option                     | Description                                                                                   |
|----------------------------|-----------------------------------------------------------------------------------------------|
| `-i, --interface`          | Network interface to sniff (default: `eth1`).                                                 |
| `-o, --output`             | Save captured packets to a PCAP file.                                                         |
| `--dump`                   | Display hex dump for each captured packet.                                                    |
| `--stats-interval <sec>`   | Interval in seconds for printing protocol statistics (default: 30 seconds).                     |
| `--filter <protocol>`      | Filter output to display only packets of a specified protocol (e.g. `IPv4`, `ARP`, `TCP`, etc.). |

### Examples

- **Capture all traffic on `eth1`:**
  ```bash
  sudo python3 NetSnoop.py -i eth1
  ```

- **Capture traffic on `eth1` and save to a PCAP file:**
  ```bash
  sudo python3 NetSnoop.py -i eth1 -o capture.pcap
  ```

- **Display hex dump and real-time statistics every 20 seconds:**
  ```bash
  sudo python3 NetSnoop.py -i eth1 --dump --stats-interval 20
  ```

- **Filter to display only IPv4 traffic:**
  ```bash
  sudo python3 NetSnoop.py -i eth1 --filter IPv4
  ```

## Configuration

You can customize NetSnoop by modifying its source code:
- **Banner & Colors:** Adjust the banner in the `print_banner()` function.
- **Protocol Parsing:** Extend or modify protocol parsers (e.g. for HTTP, DNS, etc.) as needed.
- **Statistics:** Change the stats update interval with the `--stats-interval` option.
- **Filtering:** Use the `--filter` option to display only specific types of packets.

## Security Considerations

**Important:** NetSnoop is a powerful network analysis tool. Use it responsibly and only on networks where you have explicit permission to capture traffic.

- **Ethical Use:** Intended for research and educational purposes only.
- **Privacy:** Capturing network traffic can reveal sensitive information. Handle logs and PCAP files with care.
- **Authorization:** Ensure you comply with legal and organizational policies when monitoring network traffic.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed explanation of your changes.

Please adhere to the project's coding style and include tests for new features.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

For questions, feedback, or support, please contact:  
**Email:** dynamo89247@gmail.com

---

If you find NetSnoop useful, please consider starring the repository on GitHub!

[![GitHub Stars](https://img.shields.io/github/stars/Dynamo2k1/NetSnoop.svg?style=social)](https://github.com/Dynamo2k1/NetSnoop)