import uuid


def generate_log_id():
    return str(uuid.uuid4()).replace("-", "")
