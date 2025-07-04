#!/bin/bash

PROXY_SERVER="127.0.0.1"
PROXY_PORT="8080"
services=$(networksetup -listallnetworkservices | tail -n +2)

for service in $services; do
    echo "Setting proxy for $service..."
    networksetup -setwebproxy "$service" $PROXY_SERVER $PROXY_PORT
    networksetup -setsecurewebproxy "$service" $PROXY_SERVER $PROXY_PORT
    networksetup -setwebproxystate "$service" on
    networksetup -setsecurewebproxystate "$service" on
done

echo "✅ macOS 프록시 설정 완료"
