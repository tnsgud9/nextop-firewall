import asyncio
import json
from datetime import datetime

import mitmproxy
from mitmproxy import options, http
from mitmproxy.tools import dump

from src.common.id_utils import generate_log_id
from src.firewall.logger.log_models import HttpLog
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy import Policy


def parse_http_request(flow: mitmproxy.http.HTTPFlow) -> HttpLog:
    content_type = flow.request.headers.get("Content-Type", "").lower()
    body = flow.request.content

    # Content-Type에 따라 처리
    if "application/json" in content_type:
        try:
            body = json.loads(body.decode("utf-8", "ignore"))
        except json.JSONDecodeError:
            body = "Invalid JSON format"
    elif "text/" in content_type or "application/x-www-form-urlencoded" in content_type:
        body = body.decode("utf-8", "ignore")
    else:
        body = f"Unsupported content type: {content_type}"

    # HTTPLog 객체 생성
    log = HttpLog(
        id=generate_log_id(),
        timestamp=datetime.fromtimestamp(flow.request.timestamp_start).isoformat(),
        source="mitmproxy",
        action="request",
        protocol=flow.request.scheme,
        method=flow.request.method,
        url=flow.request.url,
        reason="Captured by mitmproxy",
        headers=str(flow.request.headers),
        body=body,  # 위에서 처리한 body
    )
    return log


class MitmproxyInterceptor:
    def __init__(
        self, logger: Logger, policy: Policy, listen_host="127.0.0.1", listen_port=8080
    ):
        self.logger = logger
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._task = None
        self.policies = policy.policies

    async def request(self, flow: http.HTTPFlow):
        http_log = parse_http_request(flow)
        self.logger.http(http_log)

    async def response(self, flow: http.HTTPFlow):
        pass

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
        self._task = asyncio.create_task(self._run())
