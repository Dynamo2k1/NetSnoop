import socket
import os
import struct
import psutil
from ctypes import *

def get_ip_address(interface="eth1"):
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if interface == "eth1":
                    return addr.address
    return None

host = get_ip_address("eth1")

class IP(structure):
    _fields = [
        ("ihl",             c_ubyte,4),
        ("version",             c_ubyte,4),
        ("tos",             c_ubyte),
        ("len",             c_ushort),
        ("id",             c_ushort),
        ("offset",             c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",             c_ubyte),
        ("sum",             c_ushort),
        ("src",             c_ulong),
        ("dst",             c_ulong)
    ]
def __new__(self, socket_buffer=None):
    return self.from_buffer_copy(socket_buffer)
def __init__(self, socket_buffer=None):
    self.protocol_map = {1:"ICMP",6:"TCP", 17:"UDP"}
    self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
    self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

    try:
        self.protocol = self.protocol_map[self.protocol_num]
    except:
        self.protocol = str(self.protocol_num)


if host is None:
    print("Unable to find the IP address.")
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

    print(sniffer.recvfrom(65565))

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
