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
    method: str  # HTTP method (GET, POST, etc.)
    url: str  # Request URL
    headers: str | None  # HTTP headers (can be None for some cases)
    body: str | None  # Request/Response body (can be None if not captured)
