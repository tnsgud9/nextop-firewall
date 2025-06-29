import asyncio

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.http import HTTPFlow

class URLCapture:
   def request(self, flow: HTTPFlow) -> None:
       print(f"[URL] {flow.request.pretty_url}")

async def start_proxy():
   opts = options.Options(listen_host="127.0.0.1", listen_port=8080)
   master = DumpMaster(opts)
   master.addons.add(URLCapture())

   print("[INFO] MITM 프록시 서버 시작됨 (포트 8080)")  # 프록시 서버 시작 알림
   try:
       await master.run()
   except KeyboardInterrupt:
       await master.shutdown()

asyncio.run(start_proxy())

