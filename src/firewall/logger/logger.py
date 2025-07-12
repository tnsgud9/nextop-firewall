import asyncio

from src.firewall.logger.http_log import HttpLog
from src.firewall.logger.log import Log
from src.firewall.logger.loki import Loki
from src.firewall.logger.packet_log import PacketLog


class Logger:
    def __init__(self):
        self.send_ui_log: callable = None
        self.loki = Loki()

    def send_log(self, labels: dict, message: str):
        # asyncio.run(
        #     self.loki.send_log(labels=labels, message=message)
        # )  # 비동기 함수 실행
        self.loki.send_log(labels=labels, message=message)
        self.send_ui_log(message)

    # def get_packet_labels(self, packet: PacketLog, log_level: str) -> dict:
    #     return {
    #         "log_type": "packet",
    #         "level": log_level,
    #         "source": packet.source,
    #         "protocol": packet.protocol,
    #         "action": packet.action,
    #     }
    #
    # def get_http_labels(self, http: HttpLog, log_level: str) -> dict:
    #     return {
    #         "log_type": "packet",
    #         "level": log_level,
    #     }

    def get_labels(self, log: Log, log_level: str) -> dict:
        return {
            "log_type": "packet",
            "level": log_level,
            "source": log.source,
            "protocol": log.protocol,
            "action": log.action,
        }

    def http(self, packet: HttpLog):
        labels = self.get_labels(packet, log_level="http")
        self.send_log(labels, str(packet))

    def packet(self, packet: PacketLog):
        labels = self.get_labels(packet, log_level="packet")
        self.send_log(labels, str(packet))

    def block(self, packet: PacketLog):
        labels = self.get_packet_labels(packet, log_level="block")
        self.send_log(labels, str(packet))

    def policy(self, message: str):
        labels = {"log_type": "config", "level": "policy"}
        self.send_log(labels, message)

    def info(self, message: str):
        labels = {"log_type": "event", "level": "info"}
        self.send_log(labels, message)

    def warn(self, message: str):
        labels = {"log_type": "event", "level": "warn"}
        self.send_log(labels, message)

    def error(self, message: str):
        labels = {"log_type": "event", "level": "error"}
        self.send_log(labels, message)
