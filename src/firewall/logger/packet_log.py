from dataclasses import dataclass


@dataclass
class PacketLog:
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
