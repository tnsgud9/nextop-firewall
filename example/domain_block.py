import asyncio

from mitmproxy import http  # mitmproxy에서 HTTP 흐름을 다루기 위한 http 모듈 임포트
from mitmproxy.options import Options  # mitmproxy 설정을 위한 Options 클래스 임포트
from mitmproxy.tools.dump import DumpMaster  # mitmproxy의 DumpMaster 클래스를 통해 프록시 서버 시작

# 차단 도메인 목록
BLOCKED_DOMAINS = ["example.com", "www.google.com"]

# 도메인을 차단하는 클래스 정의
class DomainBlocker:
   # HTTP 요청을 가로챈 경우 request에 콜백이 발생
   def request(self, flow: http.HTTPFlow) -> None:
       host = flow.request.pretty_host  # 요청된 호스트 이름(도메인)을 가져옴
       if host in BLOCKED_DOMAINS:  # 요청된 도메인이 차단 목록에 있으면
           # 403 Forbidden 상태 코드와 함께 차단된 도메인에 대한 응답을 생성
           # flow.response의 값 설정시, 그 값이 자동으로 클라이언트에게 반환
           flow.response = http.Response.make(
               403,  # 상태 코드 403 (접근 금지)
               b"<h1>Access Denied Blocked Domain</h1>"  # 응답 본문: 차단된 도메인 메시지
               b"<img src='https://http.cat/403'/>",  # 403 상태를 나타내는 이미지
               {"Content-Type": "text/html"},  # 응답 헤더 설정 (HTML 콘텐츠)
           )
           print(f"[차단됨] {host}")  # 차단된 도메인 출력

# 비동기적으로 프록시 서버를 시작하는 함수

async def start_proxy():

   # 프록시 서버 옵션 설정 (127.0.0.1:8080에서 수신)

   options = Options(listen_host="127.0.0.1", listen_port=8080)

   # DumpMaster 객체 생성 (프록시 서버 관리 클래스)

   master = DumpMaster(options, with_termlog=False, with_dumper=False)

   # 도메인 차단 애드온 추가
   master.addons.add(DomainBlocker())

   print("[INFO] MITM 프록시 서버 시작됨 (포트 8080)")
   try:
       await master.run()
   except KeyboardInterrupt:
       await master.shutdown()
# 프록시 서버 실행
asyncio.run(start_proxy())
