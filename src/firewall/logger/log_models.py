from dataclasses import dataclass


@dataclass
class Log:
    id: str
    timestamp: str
    source: str
    action: str
    protocol: str
    reason: str


@dataclass
class PacketLog(Log):
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    src_port: int
    dst_port: int


@dataclass
class HttpLog(Log):
    method: str
    url: str
    headers: str | None
    body: str | None
