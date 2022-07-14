#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
IMAGE=""
targets_dir=""
cmd=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -d)
            shift
            targets_dir="$1"
            shift
            ;;
        -h)
            echo "Usage: <targets_dir> [<cmd>]"
            echo "Alternative Usage if you want to specify a docker-image: -r <image> -d <targets_dir> -c [<cmd>]"
            exit;;
        -c)
            shift
            while [ "$1" ]; do
                if [ "$1" = "-d" ] || [ "$1" = "-r" ]; then
                    break
                fi
                cmd="$cmd $1"
                shift
            done
            ;;
        -r)
            shift
            if [ "$1" = "-d" ] || [ "$1" = "-c" ]; then
                echo "Provide image-name when using -r!"
                exit
            fi
            IMAGE="$1"
            shift
            ;;
        *)
            targets_dir="$1"
            shift
            while [ "$1" ]; do
                cmd="$cmd $1"
                shift
            done
            ;;
    esac
done

if [ -z "$targets_dir" ]; then
    targets_dir="$DIR/examples"
    echo "[*] defaulting to targets_dir '$targets_dir'";
fi

[[ -d "$targets_dir" ]] || { echo "directory $targets_dir does not exist" && exit 1; }

if [ -z "$cmd" ]; then
    cmd="/bin/bash"
    echo "[*] defaulting to cmd         '$cmd'"
fi

echo "[+] Mapping local dir '$targets_dir' into container"
echo "[+] Executing command: '$cmd'"
# Map targets directory into container
if [ ! -t 0 ]; then
    docker_options="-i"
    echo "[+] Running with -i"
else
    docker_options="-it"
    echo "[+] Running with -it"
fi

if [[ -z "$IMAGE" ]]; then
    docker run \
        "$docker_options" \
        --mount type=bind,source="$(realpath $targets_dir)",target=/home/user/fuzzware/targets \
        "fuzzware:latest" $cmd
else
    echo "Runing docker with image $IMAGE"
    docker run \
        "$docker_options" \
        --mount type=bind,source="$(realpath $targets_dir)",target=/home/user/fuzzware/targets \
        "fuzzware:$IMAGE" $cmd
fi
