from __future__ import annotations

import datetime
import sys

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static


class FirewallUI(App):
    # 종료 명령어로 인식할 문자열 목록
    QUIT_BINDINGS = ["q", "quit", "Quit"]

    # 싱글턴 인스턴스 참조 (초기값 None)
    _instance: FirewallUI | None = None

    def __init__(self):
        super().__init__()
        # 인스턴스 생성 시 싱글턴 참조 저장
        FirewallUI._instance = self
        # 로그 출력을 위한 수직 컨테이너 생성
        self.log_container = Vertical()
        # 명령어 입력 위젯 생성 (placeholder 설정)
        self.command_input = Input(placeholder="명령어를 입력하세요...")

    @classmethod
    def instance(cls) -> FirewallUI:
        # 싱글턴 인스턴스 반환, 없으면 예외 발생
        if cls._instance is None:
            raise RuntimeError("FirewallUI 인스턴스가 아직 생성되지 않았습니다.")
        return cls._instance

    def compose(self) -> ComposeResult:
        """UI를 구성하는 위젯들을 순서대로 반환"""
        yield self.log_container  # 로그 출력 영역
        yield self.command_input  # 명령어 입력창

    def on_mount(self) -> None:
        """앱이 실행(마운트)된 직후 호출됨"""
        # 명령어 입력창에 자동 포커스
        self.command_input.focus()

    def append_log(
        self, message: str, datetime: datetime = datetime.datetime.now()
    ) -> None:
        """로그 메시지를 타임스탬프와 함께 로그 컨테이너에 추가"""
        timestamp = datetime.strftime("%H:%M:%S")
        log_line = Static(f"[{timestamp}] {message}")
        self.log_container.mount(log_line)  # 로그 메시지 위젯 추가
        self.log_container.scroll_end(animate=False)  # 스크롤을 맨 아래로 이동

    def generate_dummy_message(self):
        """테스트용 더미 로그 메시지 추가"""
        self.append_log("더미 로그 메시지입니다.")

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        """명령어 입력 후 엔터를 눌렀을 때 호출됨"""
        cmd = message.value.strip()  # 입력값 앞뒤 공백 제거
        self.command_input.value = ""  # 입력창 초기화
        if cmd:
            self.append_log(f"> {cmd}")  # 입력한 명령어 로그에 출력
            result = self.process_command(cmd)  # 명령어 처리
            self.append_log(result)  # 처리 결과 로그에 출력

    def process_command(self, cmd: str) -> str:
        """입력된 명령어를 해석하고 결과 메시지 반환"""
        match cmd:
            case cmd if cmd.startswith("block"):  # 'block'으로 시작하면 차단 규칙 적용
                return f"차단 규칙 적용됨: {cmd}"
            case cmd if cmd.startswith("allow"):  # 'allow'로 시작하면 허용 규칙 적용
                return f"허용 규칙 적용됨: {cmd}"
            case cmd if any(cmd.startswith(prefix) for prefix in self.QUIT_BINDINGS):
                sys.exit(0)  # 종료 명령어 입력 시 프로그램 종료
            case _:
                return f"알 수 없는 명령어: {cmd}"  # 그 외는 알 수 없는 명령어로 처리
