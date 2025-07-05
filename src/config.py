import os

from dotenv import load_dotenv

# 환경변수 로드
load_dotenv()

PROXY_IP: str = os.getenv("PROXY_IP", "127.0.0.1")
PROXY_PORT: int = os.getenv("PROXY_PORT", 8080)
LOKI_ORIGIN: str = os.getenv("LOKI_ORIGIN", "http://127.0.0.1:3100")
