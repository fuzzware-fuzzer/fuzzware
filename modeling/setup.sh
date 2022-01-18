#!/bin/bash

[[ ! -z $WORKON_HOME ]] || { echo "[ERROR] WORKON_HOME not set..."; exit 1; }

# install fuzzware with angr instead
modeling_venv_name="fuzzware-modeling"
echo "[*] Installing modeling component in venv '$modeling_venv_name'"

MODELING_VENV_PYTHON3=${MODELING_VENV_PYTHON3:-/usr/bin/python3}

# check whether installation is supported on local system due to python3 / angr compatibility
$MODELING_VENV_PYTHON3 -c 'import collections; collections.MutableMapping' &>/dev/null || {
    echo "[ERROR] Your python3 version is too high for an installation on your local system. \
The angr version which we are using requires the now removed collections.MutableMapping to be available. \
As a workaround, you may install an older version of python3 (<=3.9 should work) and set the MODELING_VENV_PYTHON3 environment variable to its path (currently, '$MODELING_VENV_PYTHON3' is used)."
    echo
    echo "Bumping angr to a higher version is currently a TODO, as angr seems to behave differently than what we used during development and upgrading requires extensive re-testing of \
the modeling outputs. However, pull requests are welcome. :-)"
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