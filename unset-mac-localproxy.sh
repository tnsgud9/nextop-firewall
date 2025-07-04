#!/bin/bash

services=$(networksetup -listallnetworkservices | tail -n +2)

for service in $services; do
    echo "Unsetting proxy for $service..."
    networksetup -setwebproxystate "$service" off
    networksetup -setsecurewebproxystate "$service" off
done

echo "✅ macOS 프록시 해제 완료"
