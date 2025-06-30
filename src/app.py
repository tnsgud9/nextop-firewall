import asyncio

from src.firewall.ui import FirewallUI


class App:
    async def run(self):
        # UI 실행
        ui = FirewallUI()

        # UI를 비동기 태스크로 실행하여 이벤트 루프를 점유하지 않고,
        # 다른 작업(패킷 캡처 등)을 동시에 실행할 수 있게 함
        asyncio.create_task(ui.run_async())

        await asyncio.Event().wait()  # 무한 대기 (앱 종료 방지)


if __name__ == "__main__":
    app = App()
    asyncio.run(app.run())
