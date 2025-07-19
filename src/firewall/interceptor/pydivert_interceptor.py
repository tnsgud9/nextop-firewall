import pydivert
import multiprocessing
import threading
import time
from datetime import datetime
from multiprocessing import Manager, Queue

from src.common.id_utils import generate_log_id
from src.firewall.logger.log_models import PacketLog
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy import Policy


class PyDivertInterceptor:
    def __init__(self, logger: Logger, policy: Policy, filter_string: str = "true"):
        self.logger = logger
        self.policy = policy
        self.filter_string = filter_string
        self.is_running = False
        self.process: multiprocessing.Process | None = None
        self.manager: Manager | None = None
        self.policy_queue: Queue | None = None
        self.log_queue: Queue | None = None

    def start(self):
        """별도 프로세스에서 interceptor 시작"""
        if self.is_running:
            return
        self.is_running = True

        # Manager 통한 IPC 설정
        self.manager = Manager()
        self.policy_queue = self.manager.Queue()
        self.log_queue = self.manager.Queue()

        # 초기 정책 전송
        self._send_policy_update()

        # 프로세스 생성 및 시작
        self.process = multiprocessing.Process(
            target=self._run_interceptor,
            args=(self.policy_queue, self.log_queue, self.filter_string),
            daemon=True,
        )
        self.process.start()

        # 로그 처리 스레드 (UI/Logger 연동 담당)
        threading.Thread(target=self._process_logs, daemon=True).start()

    def stop(self):
        """interceptor 중지"""
        if not self.is_running:
            return
        self.is_running = False

        # 프로세스 종료
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5)
        # Manager 종료
        if self.manager:
            self.manager.shutdown()

    def update_policy(self):
        """외부 호출 시 정책 업데이트 전송"""
        self._send_policy_update()

    def _send_policy_update(self):
        """현재 정책을 자식 프로세스로 전송"""
        if not self.policy_queue:
            return
        policy_data = {
            "packet": {
                name: p.__dict__
                for name, p in self.policy.get_packet_policies().items()
            },
            "http": {
                name: p.__dict__ for name, p in self.policy.get_http_policies().items()
            },
        }
        self.policy_queue.put(("policy_update", policy_data))

    def _process_logs(self):
        """자식 프로세스가 생성한 로그 수집 및 Logger 호출"""
        while self.is_running:
            if self.log_queue and not self.log_queue.empty():
                data = self.log_queue.get()
                log_obj = PacketLog(**data)
                self.logger.packet(log_obj)
            time.sleep(0.01)

    @staticmethod
    def _run_interceptor(policy_queue: Queue, log_queue: Queue, filter_string: str):
        """자식 프로세스 내부: 패킷 캡처·로깅·정책 검사·재주입"""
        current_policies = {"packet": {}, "http": {}}

        try:
            w = pydivert.WinDivert(filter_string)
            w.open()
            while True:
                # 정책 업데이트 처리
                while not policy_queue.empty():
                    msg, pdata = policy_queue.get_nowait()
                    if msg == "policy_update":
                        current_policies = pdata

                packet = w.recv()
                # PacketLog 생성
                log = PyDivertInterceptor._parse_packet(packet)
                log_queue.put(log.__dict__)

                # 정책 검사
                if not PyDivertInterceptor._check_policies(packet, current_policies):
                    w.send(packet, recalculate_checksum=True)

        except Exception:
            pass
        finally:
            try:
                w.close()
            except:
                pass

    @staticmethod
    def _parse_packet(packet) -> PacketLog:
        ts = datetime.now().isoformat()
        proto = "UNKNOWN"
        sip = dip = "N/A"
        sport = dport = -1

        if hasattr(packet, "ipv4") and packet.ipv4:
            sip, dip = packet.src_addr, packet.dst_addr
        if hasattr(packet, "tcp") and packet.tcp:
            proto, sport, dport = "TCP", packet.src_port, packet.dst_port
        elif hasattr(packet, "udp") and packet.udp:
            proto, sport, dport = "UDP", packet.src_port, packet.dst_port
        elif hasattr(packet, "icmp") and packet.icmp:
            proto = "ICMP"

        return PacketLog(
            id=generate_log_id(),
            timestamp=ts,
            source="pydivert",
            action="capture",
            protocol=proto,
            src_ip=sip,
            src_mac="N/A",
            dst_ip=dip,
            dst_mac="N/A",
            src_port=sport,
            dst_port=dport,
            reason="Captured by pydivert",
        )

    @staticmethod
    def _check_policies(packet, policies: dict) -> bool:
        for pdata in policies.get("packet", {}).values():
            if PyDivertInterceptor._match_packet_policy(packet, pdata):
                return True
        return False

    @staticmethod
    def _match_packet_policy(packet, pdata: dict) -> bool:
        try:
            if pdata.get("src_ip") and packet.src_addr != pdata["src_ip"]:
                return False
            if pdata.get("dst_ip") and packet.dst_addr != pdata["dst_ip"]:
                return False
            if pdata.get("src_port") and packet.src_port != int(pdata["src_port"]):
                return False
            if pdata.get("dst_port") and packet.dst_port != int(pdata["dst_port"]):
                return False
            return True
        except:
            return False
