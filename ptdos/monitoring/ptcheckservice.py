# external libs
from ptlibs.ptmisclib import out_if, out_ifnot, ptprint, end_error
from re import match
from validators import domain
from requests import get, exceptions
from threading import Event, Thread
from statistics import mean
from time import sleep
from sys import exit


def attack_checkservice_review(monitoring, use_json, json_obj, json_no, attackname):
    """Review data from check service, set JSON object vulnerability and status"""
    if (len(monitoring.conndata_success) + len(monitoring.conndata_failure)) == 0:
        ptcheckservice.print_error(json_obj, use_json, json_no, attackname, "Check service was not able to capture any data.")
    # evaluate data from check service
    monitoring.checkservice_review()
    # set JSON vulnerability
    json_obj.set_vulnerable(json_no, monitoring.checkservice_vulnerability())
    # set JSON status
    json_obj.set_status(json_no, "ok")


def attack_append_out_data(use_json, json_obj, json_no, attackname, duration, attack_start_time_asc, attack_end_time_asc, dst, count=None, dstport=None):
    """Append attack outcome data to JSON object or print info to console."""
    # json obj fill with general data
    json_obj.add_data(json_no, {"attack_start_time": attack_start_time_asc})
    json_obj.add_data(json_no, {"attack_end_time": attack_end_time_asc})
    json_obj.add_data(json_no, {"attack_duration": duration})
    json_obj.add_data(json_no, {"attack_destination": dst})
    if dstport:
        json_obj.add_data(json_no, {"attack_destination_port": dstport})
    # console print of general data if json not used
    ptprint(out_ifnot(f"Test finished", "INFO", use_json))  # print info to terminal
    ptprint(out_ifnot("------------------- Test parameters -------------------", "INFO", use_json, colortext=True))
    ptprint(out_ifnot(f"Test start: {attack_start_time_asc}", "INFO", use_json))
    ptprint(out_ifnot(f"Test end: {attack_end_time_asc}", "INFO", use_json))
    ptprint(out_ifnot(f"Attack type: {attackname}", "INFO", use_json))
    # additional out data for each attack
    match attackname:
        case ("smurf" | "icmpflood" | "pingofdeath"):  # packets without dstport
            json_obj.add_data(json_no, {"attack_total_packets_sent": count})
            ptprint(out_ifnot(f"Destination: {dst}, test duration: {duration} seconds", "INFO", use_json))
            ptprint(out_ifnot(f"Total of {attackname} packets sent: {count}", "INFO", use_json))
        case ("slowloris" | "rudy"):  # sockets with dstport
            json_obj.add_data(json_no, {"attack_total_concurrent_socks": count})
            ptprint(out_ifnot(f"Destination: {dst}, port: {dstport}, test duration: {duration} seconds", "INFO", use_json))
            ptprint(out_ifnot(f"Total of {attackname} concurrent sockets opened: {count}", "INFO", use_json))
        case ("udpflood" | "synflood" | "ntpampl"):  # packets with dstport
            json_obj.add_data(json_no, {"attack_total_packets_sent": count})
            ptprint(out_ifnot(f"Destination: {dst}, port: {dstport}, test duration: {duration} seconds", "INFO", use_json))
            ptprint(out_ifnot(f"Total of {attackname} packets sent: {count}", "INFO", use_json))
        case ("httpgetflood" | "httppostflood" | "httpheadflood"):  # no packets no dstport
            ptprint(out_ifnot(f"Destination: {dst}, test duration: {duration} seconds", "INFO", use_json))


def print_error(ptjsonlib, use_json, json_no, attackname, err):
    """print error to terminal or add it to json object"""
    if use_json:
        ptjsonlib.del_json(json_no)  # delete json with attack data
        ptjsonlib.add_json(attackname)  # create new error json with test_code name
        ptjsonlib.set_status(json_no, "error", err)
        # print json to console if JSON == TRUE
        ptprint(out_if(ptjsonlib.get_all_json(), "", use_json))
    # print json to console if JSON != TRUE
    ptprint(out_ifnot(err, "ERROR", use_json))
    return False


def validate_domain(mydomain):
    """Check if the domain is valid"""
    if domain(mydomain):
        return True
    return False


def format_url(url, port):
    """Adds missing http or https protocol to url address"""
    if not match('(?:http|https)://', url):
        if port == 443:
            return 'https://{}'.format(url)
        else:
            return 'http://{}'.format(url)
    return url


def get_response(url):
    """uses HTTP(s), input url must contain https:// or https://"""
    try:
        response = get(url, timeout=0.75)
        status = response.status_code
        elapsedtime_ms = response.elapsed.total_seconds()*1000  # convert to ms
        return status, elapsedtime_ms
    except exceptions.ConnectTimeout:
        return "ConnectionTimeout"
    except exceptions.ConnectionError:
        return "ConnectionError"
    except exceptions.Timeout:
        return "Timeout"
    except exceptions.HTTPError as err:
        return err
    except exceptions.InvalidSchema as err:
        return err
    except exceptions.MissingSchema as err:
        return err
    except:
        return "GetResponseGeneralError"


class CheckService:
    def __init__(self, dst, dstport):
        self.destination = dst  # IP address or url
        self.dstport = dstport  # necessary to decide if to use https or https
        self.url = format_url(self.destination, self.dstport)  # check for http/https
        self.conndata_success = []  # 200 responses from destination web server
        self.conndata_failure = []  # failure responses from destination web server
        self.conndata_responsetimes = []
        self.conndata_total = 0
        self.conndata_success_percentage = 0
        self.conndata_success_responsetimes_min = 0
        self.conndata_success_responsetimes_max = 0
        self.conndata_success_responsetimes_avg = 0
        self.monitor_before_test_responsetimes_avg = 0
        self.monitor_before_during_percentage = 0

    def checkservice_append_out_data(self, ptjsonlib, use_json, json_no):
        """append checkservice outcome data to JSON object or print info to console"""
        if use_json:
            ptjsonlib.add_data(json_no, {"checkservice_total_responses": self.conndata_total})
            ptjsonlib.add_data(json_no, {"checkservice_successful_responses": len(self.conndata_success)})
            ptjsonlib.add_data(json_no, {"checkservice_failure_responses": len(self.conndata_failure)})
            ptjsonlib.add_data(json_no, {"checkservice_successful_percentage": self.conndata_success_percentage})
            ptjsonlib.add_data(json_no, {"checkservice_response_time_ms_min": self.conndata_success_responsetimes_min})
            ptjsonlib.add_data(json_no, {"checkservice_response_time_ms_max": self.conndata_success_responsetimes_max})
            ptjsonlib.add_data(json_no, {"checkservice_response_time_ms_avg": self.conndata_success_responsetimes_avg})
            ptjsonlib.add_data(json_no, {"checkservice_response_time_before_att_ms_avg": self.monitor_before_test_responsetimes_avg})
            ptjsonlib.add_data(json_no, {"checkservice_response_time_diff_before_during_test_percentage": self.monitor_before_during_percentage})
        # console print if json not used
        ptprint(out_ifnot("------------------- CheckService report -------------------", "INFO", use_json, colortext=True))
        ptprint(out_ifnot(f"Total responses during test: {self.conndata_total}", "INFO", use_json))
        ptprint(out_ifnot(f"Successful responses during test: {len(self.conndata_success)}", "INFO", use_json))
        ptprint(out_ifnot(f"Failure responses during test: {len(self.conndata_failure)}", "INFO", use_json))
        ptprint(out_ifnot(f"Percentage of successful responses during test: {self.conndata_success_percentage} %", "INFO", use_json))
        ptprint(out_ifnot(f"Min response time during test: {self.conndata_success_responsetimes_min} ms", "INFO", use_json))
        ptprint(out_ifnot(f"Max response time during test: {self.conndata_success_responsetimes_max} ms", "INFO", use_json))
        ptprint(out_ifnot(f"Avg response time during test: {self.conndata_success_responsetimes_avg} ms", "INFO", use_json))
        ptprint(out_ifnot(f"Avg response time before test: {self.monitor_before_test_responsetimes_avg} ms", "INFO", use_json))
        ptprint(out_ifnot(f"Avg response time increase during test: {self.monitor_before_during_percentage} %", "INFO", use_json))
        ptprint(out_ifnot(f"Destination server vulnerable: {self.checkservice_vulnerability()}", "INFO", use_json))

    def checkservice_review(self):
        """"function used for data evaluation from check service"""
        # count how many values are in the field
        self.conndata_total = len(self.conndata_success) + len(self.conndata_failure)
        # % of how many 200's are in the field
        self.conndata_success_percentage = round(100 * len(self.conndata_success)/int(self.conndata_total), 2)
        # Do response time evaluation only when success responses exist
        if len(self.conndata_success) != 0:
            self.conndata_responsetimes = [row[1] for row in self.conndata_success]  # extract response times from list conndata
            self.conndata_success_responsetimes_avg = round(mean(self.conndata_responsetimes), 2)  # avg response time
            self.conndata_success_responsetimes_min = round(min(self.conndata_responsetimes), 2)  # min response time
            self.conndata_success_responsetimes_max = round(max(self.conndata_responsetimes), 2)  # max response time
            # Difference of avg response time before and during test
            self.monitor_before_during_percentage = round((100 * self.conndata_success_responsetimes_avg / self.monitor_before_test_responsetimes_avg) - 100, 2)

    def checkservice_vulnerability(self):
        """Decide if the destination server is vulnerable or not."""
        #  If there is less than 75% of 200 get response codes, server is vulnerable.
        if self.conndata_success_percentage <= 75:
            return True
        # If the average response time increased more than 500 % during test, server is vulnerable.
        if self.monitor_before_during_percentage >= 500:
            return True
        return False

    def call_checkservice_repeatedly(self, use_json):
        """Run checkservice in separate thread."""
        stopped = Event()

        def loop():
            ptprint(out_ifnot("CheckService monitoring started", "INFO", use_json))
            while not stopped.wait(1):  # the first call is in `1` secs
                response = get_response(self.url)
                # 200 is OK status for HTTP, means server is alive
                if response[0] == 200:
                    self.conndata_success.append(response)
                    response = ()
                else:
                    self.conndata_failure.append(response)
                    response = ()
            ptprint(out_ifnot("CheckService monitoring stopped", "INFO", use_json))

        Thread(target=loop).start()
        return stopped.set

    def monitoring_before_start(self, json_no, json_obj, use_json):
        """Run monitoring before attack starts and calculate avg response time."""
        ptprint(out_ifnot(f"Measuring response time of {self.destination} for 10 seconds before test starts", "INFO", use_json))
        monitoring_success = []
        n = 10
        while n > 0:
            response = get_response(self.url)
            if response[0] == 200:
                monitoring_success.append(response)
                response = ()
            n -= 1
            sleep(1)
        if len(monitoring_success) != 0:
            self.monitor_before_test_responsetimes_avg = round(mean([row[1] for row in monitoring_success]), 2)
            ptprint(out_ifnot(f"Average response time is {self.monitor_before_test_responsetimes_avg} ms", "INFO", use_json))
        else:
            end_error("Response time could not be measured, check destination availability", json_no, json_obj, use_json)
            exit(1)
