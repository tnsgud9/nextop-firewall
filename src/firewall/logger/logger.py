from src.firewall.logger.log_models import Log
from src.firewall.logger.loki import Loki


class Logger:
    def __init__(self):
        self.send_ui_log: callable = None
        self.loki = Loki()

    def send_log(self, labels: dict, message: str):
        self.loki.send_log(labels=labels, message=message)
        self.send_ui_log(message)

    def get_labels(self, log: Log, log_level: str) -> dict:
        return {
            "log_type": "packet",
            "level": log_level,
            "source": log.source,
            "protocol": log.protocol,
            "action": log.action,
        }

    def http(self, http: Log):
        labels = self.get_labels(http, log_level="http")
        self.send_log(labels, str(http))

    def packet(self, packet: Log):
        labels = self.get_labels(packet, log_level="packet")
        self.send_log(labels, str(packet))

    def block(self, packet: Log):
        labels = self.get_labels(packet, log_level="block")
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
