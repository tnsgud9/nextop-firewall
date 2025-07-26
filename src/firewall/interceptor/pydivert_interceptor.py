import pydivert
import multiprocessing
import threading
import time
import json
import hashlib
from datetime import datetime
from multiprocessing import Manager, Value, shared_memory

from src.common.id_utils import generate_log_id
from src.common.ip_locator import find_country_code
from src.firewall.logger.log_models import PacketLog
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy import Policy


class PyDivertInterceptor:
    POLICY_SHM_SIZE = 256 * 1024  # 넉넉한 고정 크기

    def __init__(self, logger: Logger, policy: Policy, filter_string: str = "true"):
        self.logger = logger
        self.policy = policy
        self.filter_string = filter_string
        self.is_running = False
        self.process = None
        self.manager = None
        self.log_queue = None
        # 공유 메모리 관련
        self.policy_shm = None
        self.policy_version = None
        self.policy_lock = None
        self._current_policy_hash = ""

    def start(self):
        """별도 프로세스에서 interceptor 시작"""
        if self.is_running:
            return
        self.is_running = True
        self.manager = Manager()
        self.log_queue = self.manager.Queue()
        self._init_shared_memory()
        self._update_shared_policy()
        self.process = multiprocessing.Process(
            target=self._run_interceptor,
            args=(
                self.log_queue,
                self.filter_string,
                self.policy_shm.name,
                self.policy_version,
                self.policy_lock,
            ),
            daemon=True,
        )
        self.process.start()
        threading.Thread(target=self._process_logs, daemon=True).start()
        threading.Thread(target=self._monitor_policy_changes, daemon=True).start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5)
        self._cleanup_shared_memory()
        if self.manager:
            self.manager.shutdown()

    def _init_shared_memory(self):
        """공유 메모리 초기화 (고정 크기)"""
        self.policy_shm = shared_memory.SharedMemory(
            create=True, size=self.POLICY_SHM_SIZE
        )
        self.policy_version = multiprocessing.Value("i", 0)
        self.policy_lock = multiprocessing.Lock()

    def _cleanup_shared_memory(self):
        try:
            if self.policy_shm:
                self.policy_shm.close()
                self.policy_shm.unlink()
        except Exception as e:
            print(f"Error cleaning up shared memory: {e}")

    def _serialize_policies(self) -> bytes:
        policy_data = {
            "packet": {
                name: p.__dict__
                for name, p in self.policy.get_packet_policies().items()
            },
            "http": {
                name: p.__dict__ for name, p in self.policy.get_http_policies().items()
            },
        }
        return json.dumps(policy_data, ensure_ascii=False).encode("utf-8")

    def _get_policy_hash(self) -> str:
        policy_data = self._serialize_policies()
        return hashlib.md5(policy_data).hexdigest()

    def _update_shared_policy(self):
        with self.policy_lock:
            try:
                policy_bytes = self._serialize_policies()
                policy_size = len(policy_bytes)
                # (크기를 체크하거나 재할당하지 않음, 고정크기 가정)
                self.policy_shm.buf[:policy_size] = policy_bytes
                self.policy_shm.buf[policy_size : self.POLICY_SHM_SIZE] = b"\0" * (
                    self.POLICY_SHM_SIZE - policy_size
                )
                with self.policy_version.get_lock():
                    self.policy_version.value += 1
                self.logger.info(
                    f"정책이 공유 메모리에 업데이트됨 (버전: {self.policy_version.value})"
                )
            except Exception as e:
                self.logger.error(f"공유 메모리 정책 업데이트 실패: {e}")

    def _monitor_policy_changes(self):
        while self.is_running:
            try:
                current_hash = self._get_policy_hash()
                if current_hash != self._current_policy_hash:
                    self._current_policy_hash = current_hash
                    self._update_shared_policy()
                    self.logger.info("정책 변경 감지됨 - 자식 프로세스에 업데이트 전송")
                time.sleep(0.5)
            except Exception as e:
                self.logger.error(f"정책 변경 감지 중 오류: {e}")
                time.sleep(1)

    def update_policy(self):
        self._current_policy_hash = ""

    def _process_logs(self):
        while self.is_running:
            try:
                if self.log_queue and not self.log_queue.empty():
                    data = self.log_queue.get_nowait()
                    log_obj = PacketLog(**data)
                    if data.get("action") == "blocked":
                        self.logger.block(log_obj)
                    else:
                        self.logger.packet(log_obj)
                time.sleep(0.01)
            except Exception as e:
                if self.is_running:
                    self.logger.error(f"로그 처리 중 오류: {e}")

    @staticmethod
    def _run_interceptor(
        log_queue, filter_string: str, policy_shm_name: str, policy_version, policy_lock
    ):
        current_policies = {"packet": {}, "http": {}}
        last_policy_version = -1
        policy_shm = None
        try:
            policy_shm = shared_memory.SharedMemory(name=policy_shm_name)
            w = pydivert.WinDivert(filter_string)
            w.open()
            while True:
                current_version = policy_version.value
                if current_version != last_policy_version:
                    with policy_lock:
                        try:
                            # policy 전체 크기에서 널 바이트(\0) 전까지 사용
                            policy_bytes = bytes(policy_shm.buf)
                            nullpos = policy_bytes.find(b"\0")
                            if nullpos > 0:
                                policy_bytes = policy_bytes[:nullpos]
                            if policy_bytes:
                                policy_data = json.loads(policy_bytes.decode("utf-8"))
                                current_policies = policy_data
                                last_policy_version = current_version
                        except Exception as e:
                            print(f"자식 프로세스 정책 업데이트 실패: {e}")
                packet = w.recv()
                log = PyDivertInterceptor._parse_packet(packet)
                should_block, block_reason = PyDivertInterceptor._check_policies(
                    packet, current_policies
                )
                if should_block:
                    log.action = "blocked"
                    log.reason = block_reason
                    log_queue.put(log.__dict__)
                else:
                    log.action = "allowed"
                    log_queue.put(log.__dict__)
                    w.send(packet, recalculate_checksum=True)
        except Exception as e:
            print(f"자식 프로세스 실행 중 오류: {e}")
        finally:
            try:
                if "w" in locals():
                    w.close()
                if policy_shm:
                    policy_shm.close()
            except Exception as e:
                print(f"자식 프로세스 정리 중 오류: {e}")

    @staticmethod
    def _parse_packet(packet) -> PacketLog:
        ts = datetime.now().isoformat()
        proto = "UNKNOWN"
        sip = dip = "N/A"
        src_country = dst_country = "N/A"
        sport = dport = -1
        try:
            if hasattr(packet, "ipv4") and packet.ipv4:
                sip, dip = packet.src_addr, packet.dst_addr
                src_country = find_country_code(sip)
                dst_country = find_country_code(dip)
            if hasattr(packet, "tcp") and packet.tcp:
                proto, sport, dport = "TCP", packet.src_port, packet.dst_port
            elif hasattr(packet, "udp") and packet.udp:
                proto, sport, dport = "UDP", packet.src_port, packet.dst_port
            elif hasattr(packet, "icmp") and packet.icmp:
                proto = "ICMP"
        except Exception:
            pass
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
            dst_country=dst_country,
            src_country=src_country,
        )

    @staticmethod
    def _check_policies(packet, policies):
        try:
            for policy_name, pdata in policies.get("packet", {}).items():
                if PyDivertInterceptor._match_packet_policy(packet, pdata):
                    action = pdata.get("action", "block")
                    reason = pdata.get("reason", f"Matched policy: {policy_name}")
                    if action == "block":
                        return True, f"Blocked by policy '{policy_name}': {reason}"
                    elif action == "capture":
                        return False, f"Captured by policy '{policy_name}': {reason}"
        except Exception as e:
            print(f"정책 검사 중 오류: {e}")
        return False, "No matching policy - default allow"

    @staticmethod
    def _match_packet_policy(packet, pdata: dict) -> bool:
        try:
            if pdata.get("src_ip") and hasattr(packet, "src_addr"):
                if packet.src_addr != pdata["src_ip"]:
                    return False
            if pdata.get("dst_ip") and hasattr(packet, "dst_addr"):
                if packet.dst_addr != pdata["dst_ip"]:
                    return False
            if pdata.get("src_port") and hasattr(packet, "src_port"):
                try:
                    if packet.src_port != int(pdata["src_port"]):
                        return False
                except (ValueError, TypeError):
                    return False
            if pdata.get("dst_port") and hasattr(packet, "dst_port"):
                try:
                    if packet.dst_port != int(pdata["dst_port"]):
                        return False
                except (ValueError, TypeError):
                    return False
            return True
        except Exception as e:
            print(f"패킷 매칭 중 오류: {e}")
            return False
