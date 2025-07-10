import json
from dataclasses import asdict

from src.firewall.logger.loki import Loki
from src.firewall.logger.packet_log import PacketLog


class Logger:
    def __init__(self):
        self.send_ui_log: callable = None
        self.loki = Loki()

    def packet(self, packet: PacketLog):
        # self.loki.send_log(
        #     labels={"log_type": "packet", "level": "info"}, message=packet_log
        # )
        self.send_ui_log(f"Packet: {packet_log}")
        pass

    def block(self, packet: PacketLog):
        pass

    def policy(self, message: str):
        pass

    def info(self, message: str):
        # self.loki.send_log(
        #     labels={"log_type": "event", "level": "info"}, message=message
        # )
        self.send_ui_log(message=message)
        pass

    def warn(self, message: str):
        self.loki.send_log(
            labels={"log_type": "event", "level": "warn"}, message=message
        )
        self.send_ui_log(message=message)
        pass

    def error(self, message: str):
        self.loki.send_log(
            labels={"log_type": "event", "level": "error"}, message=message
        )
        self.send_ui_log(message=message)
        pass

    # def PacketInfo(self, packet: PacketLog):
    #     if packet is not None:
    #         self.loki.send_log(log_type="info", packet_log=packet)
    #     self.ui_log("PacketLog: %s", json.dumps(asdict(packet), ensure_ascii=False))
