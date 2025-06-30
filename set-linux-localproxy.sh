#!/bin/bash

ENV_FILE=".env"

# Default values
DEFAULT_PROXY_IP="127.0.0.1"
DEFAULT_PROXY_PORT="8080"

# Load .env if exists
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1091
  source "$ENV_FILE"
fi

# Use default values if variables are empty
PROXY_IP="${PROXY_IP:-$DEFAULT_PROXY_IP}"
PROXY_PORT="${PROXY_PORT:-$DEFAULT_PROXY_PORT}"

PROXY="http://${PROXY_IP}:${PROXY_PORT}"

export http_proxy=$PROXY
export https_proxy=$PROXY
export ftp_proxy=$PROXY
export no_proxy="localhost,127.0.0.1,::1"

export HTTP_PROXY=$PROXY
export HTTPS_PROXY=$PROXY
export FTP_PROXY=$PROXY
export NO_PROXY="localhost,127.0.0.1,::1"

echo "mitmproxy proxy environment variables set:"
echo "http_proxy=$http_proxy"
echo "https_proxy=$https_proxy"
echo "no_proxy=$no_proxy"
