#!/usr/bin/env python3

import socket
import struct
import textwrap
import argparse
import time
import sys
import fcntl
import osgi
import threading
import json
from datetime import datetime

# Use Colorama for cross-platform color support
import colorama
colorama.init(autoreset=True)

# ANSI escape sequences (Colorama provides cross-platform support)
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
BRIGHT  = "\033[1m"
RESET   = "\033[0m"

# Constants for ioctl to set promiscuous mode
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_PROMISC  = 0x100

# Global stats dictionary
stats = {
    "IPv4": 0,
    "ARP": 0,
    "IPv6": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0,
    "DHCP": 0,
    "VLAN": 0,
    "HTTP": 0,
    "Other": 0
}
stats_lock = threading.Lock()


def print_banner():
    banner = f"""
{MAGENTA}{BRIGHT}
   _   _      _   _____                     
  | \ | | ___| |_|  ___|   _ _ __ ___  ___  
  |  \| |/ _ \ __| |_ | | | | '__/ _ \/ __| 
  | |\  |  __/ |_|  _|| |_| | | |  __/\__ \ 
  |_| \_|\___|\__|_|   \__,_|_|  \___||___/ 

NetSnoop - Ultimate Packet Sniffer {CYAN}v1.0{RESET}
Capturing live traffic in style!
{RESET}
"""
    print(banner)


def set_promiscuous_mode(sock, interface):
    """
    Enable promiscuous mode on the given interface.
    """
    ifreq = struct.pack('16sH', interface.encode('utf-8'), 0)
    try:
        res = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    except Exception as e:
        sys.exit(f"{RED}[-] Failed to get flags for {interface}: {e}{RESET}")
    flags = struct.unpack('16sH', res)[1]
    flags |= IFF_PROMISC
    ifreq = struct.pack('16sH', interface.encode('utf-8'), flags)
    try:
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)
        print(f"{GREEN}[+] Promiscuous mode enabled on {interface}{RESET}")
    except Exception as e:
        sys.exit(f"{RED}[-] Failed to set promiscuous mode on {interface}: {e}{RESET}")


def format_mac(raw_mac):
    return ":".join("{:02x}".format(b) for b in raw_mac)


def hex_dump(data, length=16):
    result = []
    for i in range(0, len(data), length):
        s = data[i:i+length]
        hexa = " ".join(f"{b:02x}" for b in s)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in s)
        result.append(f"{i:04x}   {hexa:<{length*3}}   {text}")
    return "\n".join(result)


def parse_ethernet_header(data):
    eth_header = struct.unpack("!6s6sH", data[:14])
    dest_mac = format_mac(eth_header[0])
    src_mac = format_mac(eth_header[1])
    proto = eth_header[2]  # EtherType is already in host order
    return {"dest_mac": dest_mac, "src_mac": src_mac, "proto": proto}


def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    tos = ip_header[1]
    total_length = ip_header[2]
    identification = ip_header[3]
    flags_fragment = ip_header[4]
    ttl = ip_header[5]
    protocol = ip_header[6]
    checksum = ip_header[7]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "id": identification,
        "flags_fragment": flags_fragment,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def parse_ipv6_header(data):
    ipv6_header = struct.unpack("!IHBB16s16s", data[:40])
    version = ipv6_header[0] >> 28
    traffic_class = (ipv6_header[0] >> 20) & 0xFF
    flow_label = ipv6_header[0] & 0xFFFFF
    payload_length = ipv6_header[1]
    next_header = ipv6_header[2]
    hop_limit = ipv6_header[3]
    src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[4])
    dst_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[5])
    return {
        "version": version,
        "traffic_class": traffic_class,
        "flow_label": flow_label,
        "payload_length": payload_length,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def decode_tcp_flags(flags):
    flag_names = []
    if flags & 0x01: flag_names.append("FIN")
    if flags & 0x02: flag_names.append("SYN")
    if flags & 0x04: flag_names.append("RST")
    if flags & 0x08: flag_names.append("PSH")
    if flags & 0x10: flag_names.append("ACK")
    if flags & 0x20: flag_names.append("URG")
    if flags & 0x40: flag_names.append("ECE")
    if flags & 0x80: flag_names.append("CWR")
    return ",".join(flag_names)


def parse_tcp_header(data):
    tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq = tcp_header[2]
    ack = tcp_header[3]
    offset_reserved = tcp_header[4]
    tcp_header_length = (offset_reserved >> 4) * 4
    flags = tcp_header[5]
    window = tcp_header[6]
    checksum = tcp_header[7]
    urg_ptr = tcp_header[8]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": seq,
        "acknowledgment": ack,
        "header_length": tcp_header_length,
        "flags": decode_tcp_flags(flags),
        "window": window,
        "checksum": checksum,
        "urgent_pointer": urg_ptr,
    }


def parse_udp_header(data):
    udp_header = struct.unpack("!HHHH", data[:8])
    src_port = udp_header[0]
    dst_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
    }


def parse_icmp_header(data):
    icmp_header = struct.unpack("!BBH", data[:4])
    icmp_type = icmp_header[0]
    code = icmp_header[1]
    checksum = icmp_header[2]
    return {"type": icmp_type, "code": code, "checksum": checksum}


def parse_arp_header(data):
    arp_header = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    htype = arp_header[0]
    ptype = arp_header[1]
    hlen = arp_header[2]
    plen = arp_header[3]
    opcode = arp_header[4]
    sender_mac = format_mac(arp_header[5])
    sender_ip = socket.inet_ntoa(arp_header[6])
    target_mac = format_mac(arp_header[7])
    target_ip = socket.inet_ntoa(arp_header[8])
    return {
        "htype": htype,
        "ptype": ptype,
        "hlen": hlen,
        "plen": plen,
        "opcode": opcode,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


def print_packet_info(eth, payload_info, protocol_name="", dump_data=False, raw_data=None, output_format="pretty"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if output_format == "json":
        # Create a JSON object and print it
        packet_summary = {
            "timestamp": timestamp,
            "ethernet": eth,
            "protocol": protocol_name,
            "payload": payload_info
        }
        print(json.dumps(packet_summary, indent=2))
    else:
        print(f"{CYAN}[{timestamp}]{RESET}")
        print(f"{YELLOW}Ethernet{RESET}: {eth['src_mac']} -> {eth['dest_mac']}  (Type: 0x{eth['proto']:04x})")
        if protocol_name == "IPv4":
            ip = payload_info
            print(f"{GREEN}IPv4{RESET}: {ip['src_ip']} -> {ip['dst_ip']}, Protocol: {ip.get('protocol_name', '')}, TTL: {ip['ttl']}")
            if "transport_info" in ip:
                print(f"{BLUE}Transport{RESET}: {ip['transport_info']}")
            if "http" in ip:
                print(f"{MAGENTA}HTTP Data{RESET}:\n{ip['http']}")
        elif protocol_name == "ARP":
            arp = payload_info
            print(f"{GREEN}ARP{RESET}: {arp['sender_mac']} ({arp['sender_ip']}) => {arp['target_mac']} ({arp['target_ip']}), Opcode: {arp['opcode']}")
        elif protocol_name == "IPv6":
            ipv6 = payload_info
            print(f"{GREEN}IPv6{RESET}: {ipv6['src_ip']} -> {ipv6['dst_ip']}, Next Header: {ipv6['next_header']}, Hop Limit: {ipv6['hop_limit']}")
        elif protocol_name in ("TCP", "UDP", "ICMP", "DNS", "DHCP"):
            print(f"{GREEN}{protocol_name}{RESET}: {payload_info}")
        elif protocol_name == "VLAN":
            print(f"{GREEN}VLAN{RESET}: {payload_info}")
        else:
            print(f"{GREEN}{protocol_name}{RESET}: {payload_info}")
        if dump_data and raw_data:
            print(f"{MAGENTA}Hex Dump:{RESET}")
            print(hex_dump(raw_data))
        print("-" * 80)


def write_pcap_global_header(f):
    # PCAP Global Header (24 bytes)
    global_header = struct.pack("=IHHIIII",
                                0xa1b2c3d4,  # Magic number
                                2,           # Major version
                                4,           # Minor version
                                0,           # GMT correction
                                0,           # Accuracy of timestamps
                                65535,       # Max length
                                1)           # Data link type (Ethernet)
    f.write(global_header)


def write_pcap_packet(f, packet_data):
    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    incl_len = orig_len = len(packet_data)
    packet_header = struct.pack("=IIII", ts_sec, ts_usec, incl_len, orig_len)
    f.write(packet_header)
    f.write(packet_data)


def stats_thread_func(interval):
    while True:
        time.sleep(interval)
        with stats_lock:
            print(f"\n{BRIGHT}{CYAN}[Stats] Current Packet Counts:{RESET}")
            for proto, count in stats.items():
                print(f"  {proto}: {count}")
            print()


def update_stats(proto_key):
    with stats_lock:
        if proto_key in stats:
            stats[proto_key] += 1
        else:
            stats["Other"] += 1


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="NetSnoop - Ultimate Packet Sniffer",
        epilog="Run with sudo: sudo python3 NetSnoop.py -i <interface> [-o <output_file>] [--dump] [--stats-interval <seconds>] [--filter <protocol>] [--format <pretty|json>] [--src <ip>] [--dst <ip>]"
    )
    parser.add_argument("-i", "--interface", type=str, default="eth1", help="Interface to sniff (default: eth1)")
    parser.add_argument("-o", "--output", type=str, help="Optional: Save captured packets to a PCAP file")
    parser.add_argument("--dump", action="store_true", help="Display hex dump for each packet")
    parser.add_argument("--stats-interval", type=int, default=30, help="Interval in seconds for printing stats (default: 30)")
    parser.add_argument("--filter", type=str, help="Filter to display only packets of the specified protocol (e.g. IPv4, ARP, IPv6, TCP, UDP, ICMP, DNS, DHCP, VLAN, HTTP)")
    parser.add_argument("--format", type=str, choices=["pretty", "json"], default="pretty", help="Output format: pretty (default) or json")
    parser.add_argument("--src", type=str, help="Filter by source IP address")
    parser.add_argument("--dst", type=str, help="Filter by destination IP address")
    parser.add_argument("--log-file", type=str, help="Optional: Log packet summaries (in JSON) to a file")
    args = parser.parse_args()

    log_file = None
    if args.log_file:
        try:
            log_file = open(args.log_file, "a")
        except Exception as e:
            sys.exit(f"{RED}[-] Failed to open log file: {e}{RESET}")

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sniffer.bind((args.interface, 0))
    except PermissionError:
        sys.exit(f"{RED}Error: Run with root privileges (sudo).{RESET}")
    except Exception as e:
        sys.exit(f"{RED}Error creating socket: {e}{RESET}")

    set_promiscuous_mode(sniffer, args.interface)

    pcap_file = None
    if args.output:
        try:
            pcap_file = open(args.output, "wb")
            write_pcap_global_header(pcap_file)
            print(f"{MAGENTA}[+] Saving packets to {args.output}{RESET}")
        except Exception as e:
            sys.exit(f"{RED}[-] Failed to open output file: {e}{RESET}")

    # Start stats thread
    stats_thread = threading.Thread(target=stats_thread_func, args=(args.stats_interval,), daemon=True)
    stats_thread.start()

    print(f"{MAGENTA}Starting packet capture on interface {args.interface}...{RESET}\n")
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            if pcap_file:
                write_pcap_packet(pcap_file, raw_data)
            if len(raw_data) < 14:
                continue

            eth = parse_ethernet_header(raw_data)
            eth_type = eth["proto"]

            # Check for VLAN-tagged frames
            if eth_type == 0x8100 and len(raw_data) >= 18:
                update_stats("VLAN")
                # VLAN header is 4 bytes; extract and update eth_type to the encapsulated protocol
                vlan_header = struct.unpack("!HH", raw_data[14:18])
                vlan_id = vlan_header[0] & 0x0FFF
                encapsulated_proto = vlan_header[1]
                vlan_info = {"VLAN_ID": vlan_id, "Encapsulated_Type": f"0x{encapsulated_proto:04x}"}
                # Apply filter if specified
                if args.filter and args.filter.lower() != "vlan":
                    continue
                print_packet_info(eth, vlan_info, protocol_name="VLAN", dump_data=args.dump, raw_data=raw_data, output_format=args.format)
                if log_file:
                    log_file.write(json.dumps({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "protocol": "VLAN",
                        "info": vlan_info
                    }) + "\n")
                continue

            # Process based on EtherType
            if eth_type == 0x0800:  # IPv4
                update_stats("IPv4")
                ip = parse_ip_header(raw_data[14:34])
                protocol = ip["protocol"]
                ip["protocol_name"] = ""
                transport_info = None
                if protocol == 6:  # TCP
                    update_stats("TCP")
                    ip["protocol_name"] = "TCP"
                    tcp_start = 14 + ip["ihl"]
                    transport_info = parse_tcp_header(raw_data[tcp_start:tcp_start + 20])
                    # Attempt to extract HTTP cleartext if port 80/8080
                    tcp_payload_start = tcp_start + transport_info["header_length"]
                    tcp_payload = raw_data[tcp_payload_start:14 + ip["total_length"]]
                    try:
                        http_text = tcp_payload.decode("utf-8", errors="ignore")
                        if http_text.startswith("GET") or http_text.startswith("POST") or http_text.startswith("HTTP"):
                            ip["http"] = http_text.strip()
                            update_stats("HTTP")
                    except Exception:
                        pass
                elif protocol == 17:  # UDP
                    update_stats("UDP")
                    ip["protocol_name"] = "UDP"
                    udp_start = 14 + ip["ihl"]
                    transport_info = parse_udp_header(raw_data[udp_start:udp_start + 8])
                    # Check for DNS (port 53) or DHCP (ports 67,68)
                    if transport_info.get("src_port") == 53 or transport_info.get("dst_port") == 53:
                        ip["protocol_name"] = "DNS"
                        update_stats("DNS")
                    elif transport_info.get("src_port") in (67, 68) or transport_info.get("dst_port") in (67, 68):
                        ip["protocol_name"] = "DHCP"
                        update_stats("DHCP")
                elif protocol == 1:  # ICMP
                    update_stats("ICMP")
                    ip["protocol_name"] = "ICMP"
                    icmp_start = 14 + ip["ihl"]
                    transport_info = parse_icmp_header(raw_data[icmp_start:icmp_start + 4])
                if transport_info is not None:
                    ip["transport_info"] = transport_info

                # Apply filter options (protocol, source IP, destination IP)
                if args.filter and args.filter.lower() != ip["protocol_name"].lower():
                    continue
                if args.src and args.src != ip["src_ip"]:
                    continue
                if args.dst and args.dst != ip["dst_ip"]:
                    continue

                print_packet_info(eth, ip, protocol_name="IPv4", dump_data=args.dump, raw_data=raw_data, output_format=args.format)
                if log_file:
                    log_file.write(json.dumps({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "protocol": ip["protocol_name"],
                        "info": ip
                    }) + "\n")
            elif eth_type == 0x0806:  # ARP
                update_stats("ARP")
                arp = parse_arp_header(raw_data[14:42])
                if args.filter and args.filter.lower() != "arp":
                    continue
                print_packet_info(eth, arp, protocol_name="ARP", dump_data=args.dump, raw_data=raw_data, output_format=args.format)
                if log_file:
                    log_file.write(json.dumps({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "protocol": "ARP",
                        "info": arp
                    }) + "\n")
            elif eth_type == 0x86DD:  # IPv6
                update_stats("IPv6")
                ipv6 = parse_ipv6_header(raw_data[14:54])
                if args.filter and args.filter.lower() != "ipv6":
                    continue
                print_packet_info(eth, ipv6, protocol_name="IPv6", dump_data=args.dump, raw_data=raw_data, output_format=args.format)
                if log_file:
                    log_file.write(json.dumps({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "protocol": "IPv6",
                        "info": ipv6
                    }) + "\n")
            else:
                update_stats("Other")
                if args.filter and args.filter.lower() != "other":
                    continue
                print_packet_info(eth, {"data": raw_data[14:]}, protocol_name=f"Other (0x{eth_type:04x})", dump_data=args.dump, raw_data=raw_data, output_format=args.format)
                if log_file:
                    log_file.write(json.dumps({
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "protocol": "Other",
                        "info": {"data": raw_data[14:].hex()}
                    }) + "\n")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Stopping packet capture...{RESET}")
    finally:
        if pcap_file:
            pcap_file.close()
        if log_file:
            log_file.close()
        with stats_lock:
            print(f"\n{BRIGHT}{CYAN}[Final Stats] Packet Counts:{RESET}")
            for proto, count in stats.items():
                print(f"  {proto}: {count}")
        sys.exit(0)


if __name__ == "__main__":
    main()
