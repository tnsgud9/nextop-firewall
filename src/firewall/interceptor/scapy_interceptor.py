from scapy.all import AsyncSniffer


class ScapyInterceptor:
    def __init__(self, logger):
        self.logger = logger
        self.is_running = False
        self.sniffer = AsyncSniffer(prn=self._process_packet, store=False)

    def start(self):
        # 스니퍼 시작
        self.sniffer.start()
        self.is_running = True

    def stop(self):
        # 스니퍼 중지
        self.sniffer.stop()
        self.is_running = False

    def _process_packet(self, packet) -> None:
        try:
            # 패킷 요약 정보를 UI에 출력
            summary = packet.summary()
            self.logger.info(summary)
        except Exception as e:
            # 오류 발생 시 UI에 출력
            self.ui.call_from_thread(self.ui.append_log, f"패킷 처리 중 오류 발생: {e}")
