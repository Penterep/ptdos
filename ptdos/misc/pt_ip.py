# own libs
from misc.globalfuncs import random_ip, get_local_ip
# external libs
from impacket import ImpactPacket


def set_src_ip(spoofsource):
    """If spoof true set source IP to spoofed IP, else set source IP to local IP"""
    if spoofsource:
        return random_ip()  # spoofed source IP
    else:
        return get_local_ip()  # real source IP


def create_ip_packet(src, dst, addproto):
    """Create IP packet and add protocol"""
    ip_packet = ImpactPacket.IP()
    ip_packet.set_ip_src(src)
    ip_packet.set_ip_dst(dst)

    # attach additional protocol part to IP packet
    ip_packet.contains(addproto)

    return ip_packet
