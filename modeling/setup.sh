#!/bin/bash

[[ ! -z $WORKON_HOME ]] || { echo "[ERROR] WORKON_HOME not set..."; exit 1; }

# install fuzzware with angr instead
modeling_venv_name="fuzzware-modeling"
echo "[*] Installing modeling component in venv '$modeling_venv_name'"

MODELING_VENV_PYTHON3=${MODELING_VENV_PYTHON3:-/usr/bin/python3}

# check whether installation is supported on local system due to python3 / angr compatibility
$MODELING_VENV_PYTHON3 -c 'import sys; assert sys.version_info >= (3,8)' &>/dev/null || {
    echo "[ERROR] Your python3 version is too low for an installation on your local system."
    echo
    echo "The version of angr which is used requires Python 3.8+."
    echo "As a workaround, you may install a newer version of python3 (>=3.8 should work) and set the MODELING_VENV_PYTHON3 environment variable to its path (currently, '$MODELING_VENV_PYTHON3' is used)."
    exit 1
}

/usr/bin/python3 -m virtualenv --python=$MODELING_VENV_PYTHON3 "$WORKON_HOME/$modeling_venv_name"
venv_pip="$WORKON_HOME/$modeling_venv_name/bin/pip"
if [ ! -e "$venv_pip" ]; then
    echo "Creating virtualenv $modeling_venv_name"
    mkvirtualenv -p $MODELING_VENV_PYTHON3 $modeling_venv_name || exit 1
fi

$venv_pip install -U -r requirements.txt || exit 1
$venv_pip install -U . || exit 1

exit 0
