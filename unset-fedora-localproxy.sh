#!/bin/bash

# 1. 기본 인터페이스 찾기
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
if [ -z "$INTERFACE" ]; then
    echo "❌ 기본 네트워크 인터페이스를 찾을 수 없습니다."
    exit 1
fi
echo "🌐 기본 인터페이스: $INTERFACE"

# 2. 연결 이름 찾기
CONNECTION_NAME=$(nmcli -g GENERAL.CONNECTION device show "$INTERFACE")
if [ -z "$CONNECTION_NAME" ] || [ "$CONNECTION_NAME" = "--" ]; then
    echo "❌ '$INTERFACE'에 연결된 Connection 이름을 찾을 수 없습니다."
    exit 1
fi
echo "🧹 프록시 해제 대상 연결: $CONNECTION_NAME"

# 3. 프록시 제거
nmcli connection modify "$CONNECTION_NAME" proxy.method none
nmcli connection modify "$CONNECTION_NAME" proxy.http ""
nmcli connection modify "$CONNECTION_NAME" proxy.https ""

# 4. 적용
nmcli connection down "$CONNECTION_NAME"
nmcli connection up "$CONNECTION_NAME"

echo "✅ 프록시가 해제되었습니다."
