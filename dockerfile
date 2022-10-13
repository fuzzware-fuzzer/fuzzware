from ubuntu:18.04
env LANG=C.UTF-8 LC_ALL=C.UTF-8
run apt-get update && apt-get upgrade -y && apt-get install -y python python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi gnuplot llvm
run pip3 install virtualenv virtualenvwrapper cython setuptools

arg USER_ID
arg GROUP_ID
run useradd -l -u $USER_ID -d /home/user user
run mkdir /home/user && chown -R user:user /home/user && echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

# Setup virtualenv
# 1. Base Python requirements
ENV WORKON_HOME=/home/user/.virtualenvs
ENV FUZZWARE=/home/user/fuzzware
copy pipeline/requirements.txt /requirements-pipeline.txt
copy emulator/requirements.txt /requirements-emulator.txt
copy modeling/requirements.txt /requirements-modeling.txt
user user
run python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling
run . $WORKON_HOME/fuzzware-modeling/bin/activate && pip install -r /requirements-modeling.txt
user root
run pip3 install -r /requirements-pipeline.txt
run pip3 install -r /requirements-emulator.txt

run mkdir $FUZZWARE

# 2. Install emulator side of things
copy --chown=user emulator $FUZZWARE/emulator
workdir $FUZZWARE/emulator
user user
run ./get_afl.sh
run UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZWARE/emulator/afl clean all
run make -C $FUZZWARE/emulator/AFLplusplus clean all

workdir $FUZZWARE/emulator/unicorn
run ./build_unicorn.sh
run make -C $FUZZWARE/emulator/harness/fuzzware_harness/native clean all
user root
run pip3 install -e $FUZZWARE/emulator/harness

# 3. Pipeline
copy --chown=user pipeline $FUZZWARE/pipeline
run pip3 install -e $FUZZWARE/pipeline

# 4. Modeling
copy --chown=user modeling $FUZZWARE/modeling
user user
run . $WORKON_HOME/fuzzware-modeling/bin/activate && pip install $FUZZWARE/modeling

workdir $FUZZWARE/targets
# entrypoint ["fuzzware-start-tmux-docker"]
