#!/usr/bin/env python3
import socket
import os
import struct
import psutil
from ctypes import *


def get_ip_address(interface="eth1"):
    for iface, addrs in psutil.net_if_addrs().items():
        if iface == interface:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
    return None


host = get_ip_address("eth1")


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),  # Changed from c_ulong to c_uint32 (4 bytes)
        ("dst", c_uint32)  # Changed from c_ulong to c_uint32 (4 bytes)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        # Convert source and destination addresses from 32-bit int to dotted-quad string.
        self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)


if host is None:
    print("Unable to find the IP address on the specified interface.")
    exit(1)
else:
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            # The IP header is 20 bytes (if no options are present).
            ip_header = IP(raw_buffer[0:20])
            print(f"Protocol: {ip_header.protocol}, {ip_header.src_address} -> {ip_header.dst_address}")
    except KeyboardInterrupt:
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
