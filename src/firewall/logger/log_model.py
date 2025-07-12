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
    id: str
    timestamp: str
    source: str
    action: str
    protocol: str
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    src_port: int
    dst_port: int
    reason: str


@dataclass
class HttpLog(Log):
    id: str
    timestamp: str  # Timestamp of the log entry
    source: str  # Source of the log (e.g., 'mitmproxy')
    action: str  # Action type (e.g., 'request' or 'response')
    protocol: str  # HTTP protocol (e.g., 'HTTP/1.1', 'HTTP/2')
    method: str  # HTTP method (GET, POST, etc.)
    url: str  # Request URL
    reason: str  # Reason or status message (e.g., "OK" for status code 200)
    headers: str | None  # HTTP headers (can be None for some cases)
    body: str | None  # Request/Response body (can be None if not captured)
