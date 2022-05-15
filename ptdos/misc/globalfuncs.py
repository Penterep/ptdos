from os import urandom
from os.path import realpath, join, dirname
from random import choices, randint
from string import ascii_letters, digits
from json import load
from platform import system
from ptlibs.ptmisclib import out_ifnot, ptprint
from socket import socket, AF_INET, SOCK_DGRAM, gethostbyname, gaierror
from ipaddress import ip_address
from urllib.parse import urlparse
from shutil import which


def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    return which(name) is not None


def parse_url(dst):
    """Parse url and return hostname, port, and path"""
    url = urlparse(dst)
    return url


def generate_payload(attacktype, length=128):
    """Return payload for given attack type"""
    match attacktype:
        case ("icmpflood" | "smurf" | "udpflood"):
            return bytes(urandom(length))
        case "pingofdeath":
            if system() == "Darwin":  # Darwin means macOS for some reason
                return bytes(urandom(8192))  # macOS max icmp size is 8192
            else:
                return bytes(urandom(65515))  # 65515 is max allowed size of payload for a IPv4 packet


def get_ip_from_dst(dst):
    """enter url/domain and return IP"""
    try:
        ip_add = gethostbyname(dst)
        return ip_add
    except gaierror as err:
        return err


def get_local_ip():
    """Get local IP address"""
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ip = sock.getsockname()[0]
    sock.close()
    return ip


def generate_string(length):
    """Generate random string of given length"""
    return ''.join(choices(ascii_letters + digits, k=length))


def get_root_dir():
    """Get root directory of ptdos"""
    return realpath(join(dirname(__file__), '..'))


def load_user_agents(attackname=None):
    """Load user agents from useragents.json"""
    with open(join(__file__.rsplit("/", 1)[0], "user_agents.json")) as f:
        data = load(f)
        user_agents = data['user_agents']
        accept_lang = data['accept_lang']
    if attackname == "rudy":
        return user_agents
    return user_agents, accept_lang


def validate_ip_address(ip_addr):
    """Validate IP address"""
    try:
        ip_address(ip_addr)
        return True
    except:
        return False


def os_not_comp(attackname, reason):
    """Print error message and exit if OS is not compatible"""
    ptprint(out_ifnot(f"{attackname} attack is not compatible with host OS, because {reason}.", "ERROR", colortext=True))
    exit(0)


def os_compatibility(attacktype, spoofesource=False):
    """Check if OS is compatible with attack"""
    match attacktype:
        case ("smurf" | "ntpampl" | "synflood" | "pingofdeath"):
            if system() == "Darwin":  # Darwin means macOS for some reason
                os_not_comp(attacktype, "it is not supported by the macOS")
        case "icmpflood":
            if (system() == "Darwin") and (spoofesource == True):
                os_not_comp(attacktype, "macOS does not allow spoofing source IP")
    if system() == ("Java" or "Windows" or ""):
        os_not_comp(attacktype, "ptdos supports only Linux or macOS")


def random_ip():
    """Generate random IP address, first octet from 1 to 255, remaining three from 0 to 255"""
    ip = ''
    ip += str(randint(1, 255))   # first octet
    for _ in range(3):
        ip += '.'   # dot between octets
        ip += str(randint(0, 255))   # octet 2-4
    return ip


def random_port():
    """Generate random port from 1 to 65535"""
    return randint(1, 65535)
