# src/firewall/interceptor/mitmproxy_interceptor.py
import asyncio
from mitmproxy import options, http
from mitmproxy.tools import dump

# 차단 도메인 목록
BLOCKED_DOMAINS = ["example.com", "www.google.com"]


class MitmproxyInterceptor:
    def __init__(self, logger, listen_host="127.0.0.1", listen_port=8080):
        self.logger = logger
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._task = None

    async def request(self, flow: http.HTTPFlow):
        summary = f"Request: {flow.request.method} {flow.request.url}"
        self.logger.info(summary)
        if flow.request.host in BLOCKED_DOMAINS:
            flow.response = http.Response.make(
                403, b"Blocked by firewall", {"Content-Type": "text/plain"}
            )
            self.logger.info(f"Blocked: {flow.request.url}")

    async def response(self, flow: http.HTTPFlow):
        summary = f"Response: {flow.response.status_code} {flow.request.url}"
        self.logger.info(summary)

    async def _run(self):
        opts = options.Options(
            listen_host=self.listen_host, listen_port=self.listen_port
        )
        master = dump.DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        master.addons.add(self)
        await master.run()

    def start(self):
        # asyncio.create_task로 비동기 실행
        self._task = asyncio.create_task(self._run())
