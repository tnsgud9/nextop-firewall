#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Determine which shell configuration file to use
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC_FILE="$HOME/.zshrc"  # Zsh is used
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC_FILE="$HOME/.bashrc"  # Bash is used
else
    echo "Unsupported shell. This script works with bash and zsh."
    exit 1
fi

# Remove proxy settings from the shell configuration file
if grep -q "export http_proxy" "$SHELL_RC_FILE"; then
    # Remove the proxy-related lines from the configuration file
    sed -i '/export http_proxy/d' "$SHELL_RC_FILE"
    sed -i '/export https_proxy/d' "$SHELL_RC_FILE"
    sed -i '/export ftp_proxy/d' "$SHELL_RC_FILE"
    sed -i '/export no_proxy/d' "$SHELL_RC_FILE"
    sed -i '/export HTTP_PROXY/d' "$SHELL_RC_FILE"
    sed -i '/export HTTPS_PROXY/d' "$SHELL_RC_FILE"
    sed -i '/export FTP_PROXY/d' "$SHELL_RC_FILE"
    sed -i '/export NO_PROXY/d' "$SHELL_RC_FILE"

    echo "Proxy settings removed from $SHELL_RC_FILE"
else
    echo "No proxy settings found in $SHELL_RC_FILE"
fi

# Inform the user to source the file or restart the terminal
echo "Please run 'source $SHELL_RC_FILE' or restart the terminal to apply the changes."
