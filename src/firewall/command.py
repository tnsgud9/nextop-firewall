_command_handlers: dict[str, callable] = {}


def command(name: str):
    def decorator(func: callable):
        if _command_handlers.get(name):
            raise Exception(
                f"The @command decorator should not be applied multiple times."
            )
        _command_handlers[name] = func
        return func

    return decorator


def get_command_handler(cmd: str) -> tuple[callable, str] | None:
    for prefix in _command_handlers:
        if cmd.startswith(prefix):
            return _command_handlers[prefix], cmd[len(prefix) :].strip()
    return None


async def executeCommand(cmd: str, controller):
    handler_entry = get_command_handler(cmd)

    if handler_entry is None:
        return None

    command_func, arg = handler_entry
    exec_result = await command_func(controller, arg)
    return exec_result
