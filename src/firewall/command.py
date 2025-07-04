from dataclasses import dataclass
from typing import Callable, Dict


_command_handlers: Dict[str, Callable] = {}


@dataclass
class CommandResult:
    action: str
    data: str


def command(name: str):
    def decorator(func: Callable):
        if _command_handlers.get(name):
            raise Exception(
                f"The @command decorator should not be applied multiple times."
            )
        _command_handlers[name] = func
        return func

    return decorator


def get_command_handler(cmd: str) -> tuple[Callable, str] | None:
    for prefix in _command_handlers:
        if cmd.startswith(prefix):
            return _command_handlers[prefix], cmd[len(prefix) :].strip()
    return None


async def executeCommand(cmd: str, controller) -> CommandResult | None:
    handler_entry = get_command_handler(cmd)

    if handler_entry is None:
        return None

    command_func, arg = handler_entry
    exec_result = await command_func(controller, arg)
    return exec_result
