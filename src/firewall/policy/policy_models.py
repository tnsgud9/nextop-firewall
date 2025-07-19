from dataclasses import dataclass, field


@dataclass
class PolicyBase:
    reason: str
    action: str


@dataclass
class PacketPolicy(PolicyBase):
    src_ip: str | None
    src_mac: str | None
    src_port: int | None
    dst_ip: str | None
    dst_mac: str | None
    dst_port: int | None


@dataclass
class HttpPolicy(PolicyBase):
    method: str | None
    url: str | None
    headers: str | None
    body: str | None
