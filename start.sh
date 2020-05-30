#!/bin/bash
apt-get install screen
ln -s /home/rclone/rclone /usr/bin/rclone
chmod +x /home/rclone/rclone
chmod +x /home/rclone/rclone.sh
rclone config --config /home/rclone/rclone.conf
/home/rclone/rclone.sh start
wget -O ardnspod https://raw.githubusercontent.com/dzhl/script/master/ardnspod && chmod +x ardnspod && ./ardnspod
wget -O gc.sh https://raw.githubusercontent.com/dzhl/script/master/gc.sh && chmod +x gc.sh && ./gc.sh
