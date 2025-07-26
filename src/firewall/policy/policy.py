import json

from src.firewall.policy.policy_models import PacketPolicy, HttpPolicy


class Policy:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.policies = {
            "packet": {},
            "http": {},
        }  # 빈 dict로 초기화
        self.load()

    def load(self):
        try:
            with open(self.filepath, "r") as f:
                self.policies = json.load(f)
                for key, value in self.policies["http"].items():
                    self.policies["http"][key] = HttpPolicy(**value)
                for key, value in self.policies["packet"].items():
                    self.policies["packet"][key] = PacketPolicy(**value)

            if not self.policies:  # 파일이 비어있으면 기본 폼 적용
                self.save()
        except (
            FileNotFoundError,
            json.JSONDecodeError,
        ):  # 파일이 없거나 JSON 파싱 오류
            self.save()

    def save(self):
        serializable_policies = {}
        for policy_type, policies in self.policies.items():
            serializable_policies[policy_type] = {}
            for name, policy in policies.items():
                if isinstance(policy, dict):
                    serializable_policies[policy_type][name] = policy
                else:
                    serializable_policies[policy_type][name] = policy.__dict__
        with open(self.filepath, "w") as f:
            json.dump(serializable_policies, f, indent=4)

    def get_packet_policies(self) -> dict:
        return self.policies.get("packet", {})

    def get_http_policies(self) -> dict:
        return self.policies.get("http", {})

    def add_policy(
        self,
        policy_type: str,
        policy_name: str,
        policy_info: PacketPolicy | HttpPolicy,
    ):
        if (
            isinstance(policy_info, (PacketPolicy, HttpPolicy))
            and policy_type in self.policies
        ):
            self.policies[policy_type][policy_name] = policy_info
            self.save()
        else:
            raise ValueError(f"잘못된 정책 입력")

    def delete_policy(self, policy_type: str, policy_name: str):
        if policy_type not in self.policies:
            raise ValueError(f"잘못된 정책 타입 입력")

        if policy_name not in self.policies[policy_type]:
            raise ValueError(f"잘못된 정책명 입력")

        del self.policies[policy_type][policy_name]
        self.save()  # 변경된 내용을 저장
