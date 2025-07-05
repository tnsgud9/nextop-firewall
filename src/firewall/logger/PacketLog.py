from dataclasses import dataclass


@dataclass
class PacketLog:
    id: str
    timestamp: str
    source: str
    action: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    reason: str
