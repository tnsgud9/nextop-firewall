import pydivert
import multiprocessing
import threading
import json
import time
from datetime import datetime
from src.common.id_utils import generate_log_id
from src.common.ip_locator import find_country_code
from src.firewall.logger.log_models import PacketLog


def serialize_policies(policy):
    # policy 인스턴스에서 직렬화 dict로 만들기 (직접 json.dumps 하지 않아도 됨)
    return json.dumps(
        {
            "packet": {k: v.__dict__ for k, v in policy.get_packet_policies().items()},
            "http": {k: v.__dict__ for k, v in policy.get_http_policies().items()},
        }
    )


class PyDivertInterceptor:
    def __init__(self, logger, policy, filter_string="true"):
        self.logger = logger
        self.policy = policy
        self.filter_string = filter_string
        self.is_running = False
        self.log_queue = multiprocessing.Queue()
        self.policy_queue = multiprocessing.Queue()
        self.process = None

    def start(self):
        self.is_running = True
        # 최초 정책 한번 push
        self.policy_queue.put(serialize_policies(self.policy))
        # 별도 프로세스 시작 (패킷 인터셉터)
        self.process = multiprocessing.Process(
            target=self._run_child,
            args=(self.log_queue, self.policy_queue, self.filter_string),
            daemon=True,
        )
        self.process.start()
        # 로그 소비용 쓰레드
        threading.Thread(target=self._log_worker, daemon=True).start()
        # 정책 변경 감시용 쓰레드
        threading.Thread(target=self._policy_monitor, daemon=True).start()

    def _policy_monitor(self):
        last = ""
        while self.is_running:
            pol_json = serialize_policies(self.policy)
            if pol_json != last:
                self.policy_queue.put(pol_json)
                last = pol_json
            time.sleep(0.5)

    def _log_worker(self):
        while self.is_running:
            try:
                data = self.log_queue.get(timeout=1)
                log = PacketLog(**data)
                if log.action == "blocked":
                    self.logger.block(log)
                else:
                    self.logger.packet(log)
            except Exception:
                pass

    @staticmethod
    def _run_child(log_queue, policy_queue, filter_string):
        cur_policy = {"packet": {}, "http": {}}
        w = None
        try:
            w = pydivert.WinDivert(filter_string)
            w.open()
            last_policy = ""
            while True:
                # 정책 최신화
                while not policy_queue.empty():
                    last_policy = policy_queue.get()
                    cur_policy = json.loads(last_policy)
                pkt = w.recv()
                log = PyDivertInterceptor._parse(pkt)
                should_block, reason = PyDivertInterceptor._check(pkt, cur_policy)
                log.action, log.reason = (
                    ("block", reason) if should_block else ("capture", reason)
                )
                log_queue.put(log.__dict__)
                if not should_block:
                    w.send(pkt, recalculate_checksum=True)
        finally:
            if w:
                w.close()

    @staticmethod
    def _parse(pkt):
        ts = datetime.now().isoformat()
        proto = "UNKNOWN"
        src_ip = dst_ip = "N/A"
        src_port = dst_port = -1
        src_country = dst_country = "N/A"
        try:
            if hasattr(pkt, "ipv4") and pkt.ipv4:
                src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
                src_country = find_country_code(src_ip)
                dst_country = find_country_code(dst_ip)
            if hasattr(pkt, "tcp") and pkt.tcp:
                proto, src_port, dst_port = "TCP", pkt.src_port, pkt.dst_port
            elif hasattr(pkt, "udp") and pkt.udp:
                proto, src_port, dst_port = "UDP", pkt.src_port, pkt.dst_port
            elif hasattr(pkt, "icmp") and pkt.icmp:
                proto = "ICMP"
        except Exception:
            pass
        return PacketLog(
            id=generate_log_id(),
            timestamp=ts,
            source="pydivert",
            action="capture",
            protocol=proto,
            src_ip=src_ip,
            src_mac="N/A",
            dst_ip=dst_ip,
            dst_mac="N/A",
            src_port=src_port,
            dst_port=dst_port,
            reason="Captured",
            dst_country=dst_country,
            src_country=src_country,
        )

    @staticmethod
    def _check(pkt, policies):
        try:
            for name, p in policies.get("packet", {}).items():
                if PyDivertInterceptor._match(pkt, p):
                    action = p.get("action", "block")
                    reason = p.get("reason", f"Matched: {name}")
                    if action == "block":
                        return True, f"Blocked by {name}: {reason}"
                    elif action == "capture":
                        return False, f"Captured by {name}: {reason}"
        except Exception as e:
            print("[PyDivert] 패킷 정책 검사 오류:", e)
        return False, "Captured by pydivert"

    @staticmethod
    def _match(pkt, p):
        try:
            if p.get("src_ip") and getattr(pkt, "src_addr", None) != p["src_ip"]:
                return False
            if p.get("dst_ip") and getattr(pkt, "dst_addr", None) != p["dst_ip"]:
                return False
            if p.get("src_port") and getattr(pkt, "src_port", None) != int(
                p["src_port"]
            ):
                return False
            if p.get("dst_port") and getattr(pkt, "dst_port", None) != int(
                p["dst_port"]
            ):
                return False
            return True
        except Exception:
            return False
