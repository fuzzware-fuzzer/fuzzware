FROM ubuntu:22.04 as fuzzware-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi && \
    pip3 install virtualenv virtualenvwrapper cython setuptools

ENV FUZZWARE=/home/user/fuzzware
ENV WORKON_HOME=/home/user/.virtualenvs
RUN useradd -l -u 1000 -d /home/user user && \
    mkdir -p $FUZZWARE /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

RUN USER=user GROUP=user VERSION=0.5.1 && \
    wget https://github.com/boxboat/fixuid/releases/download/v$VERSION/fixuid-$VERSION-linux-amd64.tar.gz && \
    tar -C /usr/local/bin -xzf fixuid-$VERSION-linux-amd64.tar.gz && \
    chown root:root /usr/local/bin/fixuid && \
    chmod 4755 /usr/local/bin/fixuid && \
    mkdir -p /etc/fixuid && \
    printf "user: $USER\ngroup: $GROUP\npaths:\n  - /home/user/.cache\n" > /etc/fixuid/config.yml


# Modeling container
FROM fuzzware-base as fuzzware-modeling
USER user
# First copy and install requirements
COPY modeling/requirements.txt /requirements-modeling.txt
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install -r /requirements-modeling.txt
# Then copy and install modeling, then we don't need to install the requirements on each code change
COPY --chown=user modeling $FUZZWARE/modeling
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install $FUZZWARE/modeling


# Main container
FROM fuzzware-base as fuzzware
USER root
# As above install requirements first
COPY pipeline/requirements.txt /requirements-pipeline.txt
COPY emulator/requirements.txt /requirements-emulator.txt
RUN pip3 install -r /requirements-emulator.txt -r /requirements-pipeline.txt
# Build and install emulator dependencies: afl, unicorn
COPY --chown=user emulator/get_afl.sh emulator/afl.patch $FUZZWARE/emulator/
COPY --chown=user emulator/unicorn/ $FUZZWARE/emulator/unicorn
WORKDIR $FUZZWARE/emulator
USER user
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZWARE/emulator/afl clean all && \
    make -C $FUZZWARE/emulator/AFLplusplus clean all && \
    cd $FUZZWARE/emulator/unicorn && \
    ./build_unicorn.sh

# Then copy and install emulator and pipeline
COPY --chown=user emulator $FUZZWARE/emulator
RUN make -C $FUZZWARE/emulator/harness/fuzzware_harness/native clean all
COPY --chown=user pipeline $FUZZWARE/pipeline
USER root
RUN pip3 install -e $FUZZWARE/emulator/harness && \
    pip3 install -e $FUZZWARE/pipeline

# Finally copy the modeling venv
COPY --chown=user --from=fuzzware-modeling $WORKON_HOME/ $WORKON_HOME/

USER user:user
WORKDIR $FUZZWARE/targets
entrypoint ["fixuid", "-q"]
# entrypoint ["fuzzware-start-tmux-docker"]
