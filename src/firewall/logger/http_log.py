from dataclasses import dataclass

from src.firewall.logger.log import Log


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
    headers: dict | None  # HTTP headers (can be None for some cases)
    body: str | None  # Request/Response body (can be None if not captured)
