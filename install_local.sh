#!/bin/bash
VENV_NAME=fuzzware

for i in python2 python3 automake redis-server tmux virtualenvwrapper.sh cmake clang clang++ git unzip; do

  T=$(which "$i" 2>/dev/null)

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found. It requires an install."
    exit 1

  fi

done

if [[ ! -e emulator/setup.sh || ! -e pipeline/setup.sh ]]; then
    ./update.sh
fi

if [[ ! -e emulator/setup.sh || ! -e pipeline/setup.sh ]]; then
    echo "[ERROR] Could not pull emulator and pipeline repos, exiting."; exit 1
fi

VIRTUALENVWRAPPER_PYTHON="${VIRTUALENVWRAPPER_PYTHON:=$(which python3)}"
export VIRTUALENVWRAPPER_PYTHON
source "$(which virtualenvwrapper.sh)"
"$VIRTUALENVWRAPPER_PYTHON" -c "import virtualenvwrapper" &> /dev/null || {
    echo "Module virtualenvwrapper not installed, installing now"
    "$VIRTUALENVWRAPPER_PYTHON" -m pip install virtualenvwrapper || {
        echo "Could not install virtualenvwrapper, exiting"; exit 1
    }
}

# First run modeling install as this may cause python compatibility issues
pushd modeling; ./setup.sh || { echo "Could not install modeling, exiting."; popd; exit 4; }; popd

workon $VENV_NAME 2>/dev/null || echo "Creating virtualenv '$VENV_NAME'"; mkvirtualenv -p /usr/bin/python3 $VENV_NAME 1>/dev/null 2>&1 && workon $VENV_NAME
pushd emulator; ./setup.sh || { echo "Could not install emulator, exiting. In case python / setuptools seems problematic, consider nuking the '$VENV_NAME' and '$VENV_NAME-modeling' virtualenvs and try again."; popd; exit 2; }; popd
pushd pipeline; ./setup.sh || { echo "Could not install pipeline, exiting."; popd; exit 3; }; popd
