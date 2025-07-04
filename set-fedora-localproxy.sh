#!/bin/bash

PROXY="http://127.0.0.1:8080"

# 1. 기본 인터페이스 찾기
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
if [ -z "$INTERFACE" ]; then
    echo "❌ 기본 네트워크 인터페이스를 찾을 수 없습니다."
    exit 1
fi
echo "🌐 기본 인터페이스: $INTERFACE"

# 2. 해당 인터페이스의 연결 이름 획득
CONNECTION_NAME=$(nmcli -g GENERAL.CONNECTION device show "$INTERFACE")
if [ -z "$CONNECTION_NAME" ] || [ "$CONNECTION_NAME" = "--" ]; then
    echo "❌ '$INTERFACE'에 연결된 Connection 이름을 찾을 수 없습니다."
    exit 1
fi
echo "🔧 연결 이름: $CONNECTION_NAME"

# 3. 프록시 설정
nmcli connection modify "$CONNECTION_NAME" proxy.method manual
nmcli connection modify "$CONNECTION_NAME" proxy.http "$PROXY"
nmcli connection modify "$CONNECTION_NAME" proxy.https "$PROXY"

# 4. 적용
nmcli connection down "$CONNECTION_NAME"
nmcli connection up "$CONNECTION_NAME"

echo "✅ 프록시가 [$CONNECTION_NAME] 연결에 설정되었습니다."
