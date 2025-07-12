from dataclasses import dataclass


@dataclass
class Log:
    id: str
    timestamp: str
    source: str
    action: str
    protocol: str
    reason: str
