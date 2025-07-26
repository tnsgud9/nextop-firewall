import json
import time
import requests

from src.firewall import config


class Loki:
    def __init__(self, loki_origin: str = config.LOKI_ORIGIN, log_callback=None):
        self.loki_url = f"{loki_origin}/loki/api/v1/push"
        self.log_callback = log_callback

    def send_log(
        self,
        labels: dict[str, str],
        message: str,
    ):
        headers = {"Content-Type": "application/json"}

        timestamp_ns = str(time.time_ns())

        # Loki 페이로드 구성
        loki_payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [[timestamp_ns, message]],
                }
            ]
        }

        response = requests.post(
            self.loki_url,
            headers=headers,
            data=json.dumps(loki_payload),
            proxies={"http": None, "https": None},  # 프록시 우회
        )
        response.raise_for_status()
