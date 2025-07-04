import asyncio

from src.firewall.controller import Controller
from src.firewall.ui import FirewallUI


class App:
    async def run(self):
        # logger = Logger()  # UI는 나중에 연결

        # command_filter = CommandFilter()
        # controller = Controller(logger=logger, command_filter=command_filter)

        # UI 생성 및 의존성 주입
        # ui = FirewallUI(controller=controller)
        controller = Controller()

        # UI 실행
        ui = FirewallUI(controller)

        # UI를 비동기 태스크로 실행하여 이벤트 루프를 점유하지 않고,
        # 다른 작업(패킷 캡처 등)을 동시에 실행할 수 있게 함
        asyncio.create_task(ui.run_async())

        await asyncio.Event().wait()  # 무한 대기 (앱 종료 방지)


if __name__ == "__main__":
    app = App()
    asyncio.run(app.run())
