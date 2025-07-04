from src.firewall.command import command


class Controller:
    @command("block")
    async def block_command(self, arg: str) -> str:
        return f"차단 규칙 적용됨: {arg}"

    @command("allow")
    async def allow_command(self, arg: str) -> str:
        return {}

    async def unknown_command(self, cmd: str) -> str:
        return f"알 수 없는 명령어: {cmd}"
