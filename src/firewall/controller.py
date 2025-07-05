from src.firewall.command import command
from src.firewall.logger.logger import Logger


class Controller:
    def __init__(self, logger: Logger):
        self.logger: Logger = logger

    @command("block")
    async def block_command(self, arg: str):
        self.logger.info(f"차단 규칙 적용됨: {arg}")

    @command("allow")
    async def allow_command(self, arg: str):
        return {}

    async def unknown_command(self, cmd: str):
        return f"알 수 없는 명령어: {cmd}"
