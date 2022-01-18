[[ $(id -u) -ne 0 ]] || { echo "Please run as root"; exit 1; }

echo 524288 > /proc/sys/fs/inotify/max_user_watches
echo 512 > /proc/sys/fs/inotify/max_user_instances

cat /proc/sys/fs/inotify/max_user_watches
cat /proc/sys/fs/inotify/max_user_instances