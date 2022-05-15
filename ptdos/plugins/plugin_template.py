"""ptdos extension that adds a XYZ attack."""
# python3 ptdos.py -a XYZ -d 5

# own libs
from infrastructure import factory
# external libs
from dataclasses import dataclass


@dataclass
class XYZ:

    category: str
    name: str

    def launch_attack(self, args, dst, duration, use_json, json_obj, json_no, monitoring, att_start_t_epoch, att_start_t_asc) -> None:
        """Main function responsible for launching the attack."""

        # checkservice start monitoring
        monitoringprocess = monitoring.call_checkservice_repeatedly()

    @staticmethod
    def make_help():
        """Help for attack printed out in main file ptdos.py."""
        return [
            {"XYZ attack options": [
                ["-a", "--attack", "<attack>", "Attack name - synflood"],
                ["-d", "--duration", "<duration>", "Attack duration in seconds. Default 10 seconds."],
            ]
            }
        ]

    @staticmethod
    def make_args(parser):
        """Specify arguments needed for the attack"""
        parser.add_argument("-a", "--attack", dest="attack", type=str)  # attack type


def register() -> None:
    """Register attack in factory."""
    factory.register("XYZ", XYZ)
