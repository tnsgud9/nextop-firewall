from src.firewall.command import command
from src.firewall.logger.logger import Logger
from src.firewall.policy.policy import Policy
from src.firewall.policy.policy_models import PacketPolicy, HttpPolicy


class Controller:
    def __init__(self, logger: Logger, policy: Policy):
        self.logger: Logger = logger
        self.policy: Policy = policy

    @command("block")
    async def block_command(self, arg: str):
        try:
            arguments = arg.split()
            policy_type = arguments[0]  # http, packet
            policy_name = arguments[1]  # 정책 이름
            policy_dic = {}
            kv_pairs = arguments[2:]  # 이외 정책

            for pair in kv_pairs:
                if "=" not in pair:
                    raise ValueError(f"key=value 형식이 아닙니다: {pair}")
                key, value = pair.split("=", 1)
                policy_dic[key] = value

            if policy_type == "packet":
                policy_info = PacketPolicy(
                    src_ip=policy_dic.get("src_ip"),
                    src_mac=policy_dic.get("src_mac"),
                    src_port=policy_dic.get("src_port"),
                    dst_ip=policy_dic.get("dst_ip"),
                    dst_mac=policy_dic.get("dst_mac"),
                    dst_port=policy_dic.get("dst_port"),
                    reason=policy_dic.get("reason", ""),
                    action=policy_dic.get("action", "block"),
                )
            elif policy_type == "http":
                policy_info = HttpPolicy(
                    method=policy_dic.get("method"),
                    url=policy_dic.get("url"),
                    headers=policy_dic.get("headers"),
                    body=policy_dic.get("body"),
                    reason=policy_dic.get("reason", ""),
                    action=policy_dic.get("action", "block"),
                )
            else:
                raise
            self.policy.add_policy(policy_type, policy_name, policy_info)
            self.logger.info(f"차단 규칙 적용됨: {arg}")

        except Exception as e:  # 예외가 발생했을 때 실행됨
            self.logger.info(f"잘못된 정책 유형 입력 : block {arg} : {e}")

    @command("delete")
    async def delete_command(self, arg: str):
        try:
            arguments = arg.split()
            policy_type = arguments[0]  # http, packet
            policy_name = arguments[1]  # 정책 이름
            self.policy.delete_policy(policy_type, policy_name)
        except Exception as e:  # 예외가 발생했을 때 실행됨
            self.logger.info(f"잘못된 정책 유형 입력 : block {arg} : {e}")
