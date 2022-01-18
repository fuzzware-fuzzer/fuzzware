#!/bin/bash
# Install a recent version of Docker.
# Convenience script following to https://docs.docker.com/engine/install/ubuntu/

OS_NAME="$(awk -F= '/^NAME/{print $2}' /etc/os-release)"
if [ "$OS_NAME" == '"Ubuntu"' ]; then
    if [ "$(which docker 2>/dev/null)" = "" ]; then
        sudo apt-get update
        sudo apt-get -y install \
            apt-transport-https \
            ca-certificates \
            curl \
            gnupg-agent \
            software-properties-common

        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

        sudo add-apt-repository \
            "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) \
            stable"

        sudo apt-get install -y docker-ce docker-ce-cli containerd.io
    else
        echo "Docker already installed. Exiting..."
        exit 0
    fi
else
    echo "Not running on Ubuntu. Exiting..."
    exit 1
fi
