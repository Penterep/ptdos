"""Represents a basic infrastructure attack."""
# external libs
from typing import Protocol


class InfrastructureAttack(Protocol):
    """Basic representation of a infrastructure attack."""

    def launch_attack(self) -> None:
        """Let the attack launch itself."""

    def make_help(self) -> None:
        """Let the attack make a help."""

    def make_args(self) -> None:
        """Let the attack specify arguments."""
