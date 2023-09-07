#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [[ -z "$1" ]]; then
    echo "[INFO] No cmd-line-options provided, building default-image"
    if [[ ! -e emulator/setup.sh || ! -e pipeline/setup.sh ]]; then
        "$DIR"/update.sh
    fi
    TAG="latest"
else
    echo "[INFO] Building fuzzware-image with tag: $1"
    TAG=$1
fi

if [[ ! -e emulator/setup.sh || ! -e pipeline/setup.sh ]]; then
    echo "[ERROR] Could not pull emulator and pipeline repos, exiting."; exit 1
fi

docker build -t "fuzzware:$TAG" "$DIR"