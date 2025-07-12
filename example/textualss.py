from textual.app import App
from textual.widget import Widget
from textual.reactive import reactive


class LogScreen(Widget):
    log_data = reactive([])

    def add_log(self, log_message: str):
        self.log_data.append(log_message)
        self.refresh()

    def render(self):
        logs = "\n".join(self.log_data[-10:])  # 마지막 10개의 로그만 출력
        return logs or "No logs available"


class CommandInput(Widget):
    def on_mount(self):
        self.log_screen = self.query_one(LogScreen, required=True)

    async def on_key(self, event):
        if event.key == "enter":
            command = self.text.strip()
            self.text = ""  # 입력창 비우기
            self.log_screen.add_log(f"> {command}")
            # 여기서 명령어 처리를 추가할 수 있습니다 (예: 시스템 명령 실행)

    def render(self):
        return f"[bold cyan]Command Input:[/bold cyan] {self.text}"


class LogApp(App):
    async def on_mount(self):
        # super() 호출 없이 바로 view에 위젯을 추가
        self.log_screen = LogScreen()
        self.command_input = CommandInput()

        # view가 준비되었을 때 위젯들을 도킹
        await self.view.dock(self.log_screen, edge="top")
        await self.view.dock(self.command_input, edge="bottom")

    async def on_key(self, event):
        pass


if __name__ == "__main__":
    app = LogApp()  # 인스턴스 생성
    app.run()  # 인스턴스에서 run() 메서드를 호출
