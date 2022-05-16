#!/usr/bin/python3
# external libs
import os
from argparse import ArgumentParser
from sys import path, exit, argv
from json import load
from ptlibs.ptmisclib import out_ifnot, ptprint, help_print, print_banner, end_error
from ptlibs.ptjsonlib import ptjsonlib
from time import time, asctime

# import custom libraries - used because of pypi
if __name__ != "__main__":
    path.append(__file__.rsplit("/", 1)[0])

# own libs
from infrastructure import factory, loader
from misc.globalfuncs import os_compatibility
from version import SCRIPTNAME, __version__
from monitoring.ptcheckservice import CheckService


class PtDos:
    def __init__(self, argparse_dict):
        """parse general input arguments used by all plugins"""
        self.argsjson = argparse_dict
        self.dst = argparse_dict['dst']
        self.duration = argparse_dict['duration']
        self.use_json = argparse_dict['json']
        self.json_obj = ptjsonlib(self.argsjson['json'])  # create json object
        self.json_no = self.json_obj.add_json(self.argsjson['attack'])  # add attack to json

    def run(self, attacks):
        """Run the ptdos application"""
        # print help if ptdos called without args or parameter -h or --help specified and exit
        if len(argv) == 1 or "-h" in argv or "--help" in argv:
            assemble_help(attacks)
            exit(0)

        # Attack name, destination and duration must be specified otherwise exit
        if not self.argsjson['attack'] or not self.argsjson['dst']:
            end_error("Attack name or destination is missing", self.json_no, self.json_obj, self.argsjson['json'])
            exit(1)

        # Select and launch attack specified in argument
        for attack in attacks:
            if attack.name == self.argsjson['attack']:
                # Check host OS compatibility
                os_compatibility(attack.name)

                # print Penterep Tools banner if json == false
                print_banner(SCRIPTNAME, __version__, self.argsjson['json'])
                ptprint(out_ifnot("------------------- Test status -------------------", "INFO", self.use_json, colortext=True))

                # Initialize monitoring from checkService
                monitoring = CheckService(self.dst, self.argsjson['dstport'])

                # monitoring destination before test start
                monitoring.monitoring_before_start(self.json_no, self.json_obj, self.use_json)

                # attack start time
                att_start_t_epoch = time()  # save time in seconds since epoch started (1.1.1970)
                att_start_t_asc = asctime()  # save current time
                ptprint(out_ifnot(f"Test started at {att_start_t_asc}", "INFO", self.use_json))

                # call method inside the plugin and give parsed args with json object
                attack.launch_attack(self.argsjson, self.dst, self.duration, self.use_json, self.json_obj, self.json_no, monitoring, att_start_t_epoch, att_start_t_asc)
                exit(0)  # application exit after attack done

        end_error(f"Attack '{self.argsjson['attack']}' is misspelled or does not exist", self.json_no, self.json_obj, self.argsjson['json'])
        exit(1)


def parse_args(attacks):
    """Defines parsing for input arguments from command line. Basic args stored here."""
    parser = ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-a", "--attack", dest="attack", type=str)  # attack type
    parser.add_argument("-d", "--duration", dest="duration", type=int, default=10)  # attack's duration
    parser.add_argument("-dst", "--destination", dest="dst", type=str)  # destination IP/URL
    parser.add_argument("-dp", "--dstport", dest="dstport", type=int, default=80)  # destination port
    parser.add_argument("-ss", "--spoof-source", dest="spoof-source", action="store_true", default=False)
    parser.add_argument("-dl", "--data-length", dest="datalength", type=int, default=1024)
    parser.add_argument("-sq", "--socksquant", dest="socksquant", type=int, default=10)  # Number of sockets opened
    parser.add_argument("-st", "--sleep-time", dest="sleeptime", type=float, default=0)
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    # Add arguments from each attack
    for attack in attacks:
        attack.make_args(parser)
    return parser.parse_args()


def assemble_help(attacks):
    """Assemble terminal help for each attack."""
    attacks_names = []
    helper = []

    # for each attack save its help to help array
    for attack in attacks:
        attacks_names.append(attack.name)
        helper += attack.make_help()

    # print completed help to terminal
    help_print(description_help(helper, attacks_names), SCRIPTNAME, __version__)


def description_help(helper, attacks_names):
    """Part of help containing default info about ptdos. Add data from helper in the end."""
    return [
               {"description": [
                   "Ptdos allows to test various DoS attacks against specified target."
               ]},
               {"Names of supported DoS attacks": [
                   attacks_names[0:5],
                   attacks_names[5:]
               ]},
               {"usage": [
                   "ptdos <options>"
               ]},
               {"usage_example": [
                   "ptdos -a attackname -d timeinsecs -dst x.x.x.x -dp 80 --json",
               ]},
               {"General options": [
                   ["-a", "--attack", "<attack>", "Attack name."],
                   ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
                   ["-dst", "--destination", "<dst>", "Target of the attack."],
                   ["-j", "--json", "", "Output in JSON format - True/False."],
                   ["-v", "--version", "", "Show script version and exit."],
                   ["-h", "--help", "", "Show help and exit."]
               ]
               }
           ] + helper


def main() -> None:
    """Read data from a JSON config file. Parse input arguments from cmd to JSON object and runs ptdos."""
    with open(os.path.join(__file__.rsplit("/", 1)[0], "config.json")) as file:
        data = load(file)  # load data from file
        loader.load_plugins(data["plugins"])  # load plugins
        attacks = [factory.create(item) for item in data["attacks"]]  # create attacks

    script = PtDos(vars(parse_args(attacks)))  # parse arguments
    script.run(attacks)  # start application


if __name__ == "__main__":
    main()
