from __future__ import annotations

import asyncio
import threading
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static

from src.firewall.command import executeCommand


class FirewallUI(App):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.logger = controller.logger
        self.logger.send_ui_log = self.show_log
        self.log_container = Vertical()
        self.command_input = Input(placeholder="명령어를 입력하세요...")
        self.mounted = asyncio.Event()

    def compose(self) -> ComposeResult:
        yield self.log_container  # 로그 출력 영역
        yield self.command_input  # 명령어 입력창

    def on_mount(self) -> None:
        self.command_input.focus()
        self.mounted.set()  # 마운트 완료 시점 알림

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        cmd = message.value.strip()  # 입력값 앞뒤 공백 제거
        self.command_input.value = ""  # 입력창 초기화
        if cmd:
            self.append_log(f"> {cmd}")  # 입력한 명령어 로그에 출력
            await executeCommand(cmd, self.controller)  # 명령어 처리

    def show_log(
        self,
        message: str,
        now: datetime = None,
    ):
        if threading.get_ident() == self._thread_id:
            # 현재 스레드 == UI 스레드 → 직접 호출
            self.append_log(message, now)
        else:
            # 다른 스레드에서 호출된 경우만 call_from_thread 사용
            self.call_from_thread(self.append_log, message, now)

    def append_log(
        self,
        message: str,
        now: datetime = None,
    ) -> None:
        if now is None:
            now = datetime.now()
        timestamp = str(now)[11:]
        log_line = Static(f"[{timestamp}] {message}", markup=False)
        self.log_container.mount(log_line)  # 로그 메시지 위젯 추가
        self.log_container.scroll_end(animate=False)  # 스크롤을 맨 아래로 이동

    def generate_dummy_message(self):
        self.append_log("더미 로그 메시지입니다.")
