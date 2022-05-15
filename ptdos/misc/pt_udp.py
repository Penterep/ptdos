from impacket import ImpactPacket


def create_udp_packet(data, sport, dport):
    """Create UDP packet and add data to it."""
    udp_packet = ImpactPacket.UDP()
    udp_packet.set_uh_sport(sport)  # source port
    udp_packet.set_uh_dport(dport)  # destination port
    udp_packet.contains(ImpactPacket.Data(data.encode('utf-8')))

    return udp_packet
