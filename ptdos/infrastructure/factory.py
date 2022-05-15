"""Factory for creating a infrastructure attack."""
# external libs
from typing import Any, Callable
# own libs
from infrastructure.attack import InfrastructureAttack

attack_creation_funcs: dict[str, Callable[..., InfrastructureAttack]] = {}


def register(attack_type: str, creator_fn: Callable[..., InfrastructureAttack]) -> None:
    """Register a new infrastructure attack type."""
    attack_creation_funcs[attack_type] = creator_fn


def unregister(attack_type: str) -> None:
    """Unregister a infrastructure attack type."""
    attack_creation_funcs.pop(attack_type, None)


def create(arguments: dict[str, Any]) -> InfrastructureAttack:
    """Create a infrastructure attack of a specific type, given JSON data."""
    args_copy = arguments.copy()
    attack_type = args_copy.pop("type")
    try:
        creator_func = attack_creation_funcs[attack_type]
    except KeyError:
        raise ValueError(f"unknown attack type {attack_type!r}") from None
    return creator_func(**args_copy)
