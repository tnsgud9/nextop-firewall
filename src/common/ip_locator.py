# src/firewall/utils/ip_country_resolver.py

import ipaddress
import csv
import os


# 실행 시 단 1회만 CSV 로드
def _load_ip_ranges():
    ip_ranges = []
    csv_path = os.path.join(os.path.dirname(__file__), "ipv4.csv")
    with open(csv_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            start_ip = ipaddress.IPv4Address(row["start_ip"])
            end_ip = ipaddress.IPv4Address(row["end_ip"])
            country_code = row["country_code"]
            ip_ranges.append((start_ip, end_ip, country_code))
    return ip_ranges


# 전역 범위에 로드 (한 번만 실행됨)
_ip_ranges = _load_ip_ranges()


# 이 함수만 외부에 노출
def find_country_code(ip_str):
    ip = ipaddress.IPv4Address(ip_str)
    for start_ip, end_ip, country_code in _ip_ranges:
        if start_ip <= ip <= end_ip:
            return country_code
    return "N/A"
