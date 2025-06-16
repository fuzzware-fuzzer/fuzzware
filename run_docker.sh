#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
IMAGE="latest"
targets_dir=""
cmd=""
docker_options=""
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
        --rm)
            shift
            echo "[+] Removing container after exit"
            docker_options+=" --rm"
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
docker_options+=" --mount type=bind,source=$(realpath "$targets_dir"),target=/home/user/fuzzware/targets"
echo "[+] Executing command: '$cmd'"
# Map targets directory into container
if [ ! -t 0 ]; then
    docker_options+=" -i"
    echo "[+] Running with -i"
else
    docker_options+=" -it"
    echo "[+] Running with -it"
fi

# Choose a user id for the user in the container
# a) Use user id from invoking user
user_id=$(id -u)
group_id=$(id -g)
if [[ $user_id -eq 0 || $group_id -eq 0 ]]; then
    # b) If root is invoking, try the sudoing user
    user_id=$SUDO_UID
    group_id=$SUDO_GID
    if [[ ! -z $user_id ]]; then
        echo "Using sudoing user's id to run container"
    else
        # c) If this fails, try the user owning the dockerfile
        user_id=$(stat -c "%U" $DIR/dockerfile)
        group_id=$(stat -c "%G" $DIR/dockerfile)
        if [[ $user_id -eq 0 || $group_id -eq 0 ]]; then
            # d) Everything is root owned, default to user 1000
            user_id=1000
            group_id=1000
            echo "Could not derive non-root user id from invoking user or ownership, defaulting to $user_id:$group_id"
        fi
    fi
fi

echo "[+] Changing id to $user_id:$group_id "
docker_options+=" --user $user_id:$group_id"

echo "[+] Runing docker with image $IMAGE"
docker run $docker_options "fuzzware:$IMAGE" $cmd
