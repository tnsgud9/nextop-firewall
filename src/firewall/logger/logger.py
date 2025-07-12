import json

from src.firewall.logger.loki import Loki
from src.firewall.logger.packet_log import PacketLog


class Logger:
    def __init__(self):
        self.send_ui_log: callable = None
        self.loki = Loki()

    def send_log(self, labels: dict, message: str):
        self.loki.send_log(labels=labels, message=message)
        self.send_ui_log(message)

    def get_packet_labels(self, packet: PacketLog, log_level: str) -> dict:
        return {
            "log_type": "packet",
            "level": log_level,
            "source": packet.source,
            "protocol": packet.protocol,
            "action": packet.action,
        }

    def packet(self, packet: PacketLog):
        labels = self.get_packet_labels(packet, log_level="packet")
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
