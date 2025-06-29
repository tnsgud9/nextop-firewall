import random
import string
import pydivert

PORT = 12345
filter_str = f"tcp.DstPort == {PORT} or tcp.SrcPort == {PORT}"


# 람다식으로 랜덤 문자열 생성 (바이트로 처리)
generate_random_string = lambda length: bytes(
   "".join(random.choices(string.ascii_letters + string.digits, k=length)), "utf-8"
)
with pydivert.WinDivert(filter_str) as w:
   for packet in w:
       # TCP 데이터가 있을 때만 변조 시도
       if packet.payload:
           # 클라이언트 -> 서버 방향 패킷만 변조
           if packet.dst_port == PORT:
               packet.payload =  bytes("[Modified]") + generate_random_string(len(packet.payload))
               packet.recalculate_checksums()
       w.send(packet)
