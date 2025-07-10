import threading
from src.firewall.interceptor.scapy_interceptor import ScapyInterceptor
from src.firewall.logger.logger import Logger


class Interceptor:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.scapy_interceptor = ScapyInterceptor(logger)
        self.capture_thread: threading.Thread | None = None
        self.is_running = False

    async def start_async(self):
        """비동기로 패킷 캡처 시작"""
        if self.is_running:
            return
        self.is_running = True
        self.logger.info("Interceptor starting async...")
        self.capture_thread = threading.Thread(
            target=self.scapy_interceptor.start_capture, daemon=True
        )
        self.capture_thread.start()
        self.logger.info("Interceptor started")

    def stop(self):
        """패킷 캡처 중지"""
        if not self.is_running:
            return
        self.scapy_interceptor.stop_capture()
        self.is_running = False
        self.logger.info("Interceptor stopped")
