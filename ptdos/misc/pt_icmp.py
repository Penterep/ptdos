# own libs
from misc.globalfuncs import generate_payload
# external libs
from impacket import ImpactPacket


def create_icmp_packet(attackname, payload_len=None):
    """Create ICMP packet and fill with data"""
    icmp_packet = ImpactPacket.ICMP()
    icmp_packet.set_icmp_type(icmp_packet.ICMP_ECHO)

    # fill icmp packet payload with data
    icmp_packet.contains(ImpactPacket.Data(generate_payload(attackname, payload_len)))
    return icmp_packet
