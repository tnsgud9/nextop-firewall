from __future__ import annotations

import datetime
import sys

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static

from src.firewall.command import executeCommand


class FirewallUI(App):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.log_container = Vertical()
        self.command_input = Input(placeholder="명령어를 입력하세요...")

    def compose(self) -> ComposeResult:
        yield self.log_container  # 로그 출력 영역
        yield self.command_input  # 명령어 입력창

    def on_mount(self) -> None:
        self.command_input.focus()

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        cmd = message.value.strip()  # 입력값 앞뒤 공백 제거
        self.command_input.value = ""  # 입력창 초기화
        if cmd:
            self.append_log(f"> {cmd}")  # 입력한 명령어 로그에 출력
            result = await executeCommand(cmd, self.controller)  # 명령어 처리
            if result is None:
                self.append_log(f"알 수 없는 명령어: {cmd}")
                return
            self.append_log(result)  # 처리 결과 로그에 출력

    def append_log(
        self, message: str, datetime: datetime = datetime.datetime.now()
    ) -> None:
        timestamp = datetime.strftime("%H:%M:%S")
        log_line = Static(f"[{timestamp}] {message}")
        self.log_container.mount(log_line)  # 로그 메시지 위젯 추가
        self.log_container.scroll_end(animate=False)  # 스크롤을 맨 아래로 이동

    def generate_dummy_message(self):
        self.append_log("더미 로그 메시지입니다.")
