from scapy.all import *


# 패킷 캡처 후 호출되는 콜백 함수 정의
def packet_callback(packet):
    # 캡처된 패킷의 요약(summary)을 출력합니다.
    print(f"캡처된 패킷: {packet.summary()}")


# sniff() 함수는 네트워크에서 패킷을 캡처하는 함수.
# prn 인자는 패킷이 캡처될 때마다 호출될 콜백 함수.
# 여기서는 packet_callback 함수를 설정하여 캡처된 패킷에 대한 요약 정보를 출력.
sniff(prn=packet_callback)
