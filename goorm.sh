#!/bin/bash
mkdir albany_puyizhen
mkdir albany_fengyunxiao
mkdir usc_puyizhen
mkdir p1
mkdir p2
mkdir p3
mkdir p4
apt-get install screen
wget -O rclone.zip https://raw.githubusercontent.com/dzhl/script/master/rclone.zip
unzip -o rclone.zip
ln -s /home/rclone/rclone /usr/bin/rclone
chmod +x /home/rclone/rclone
chmod +x /home/rclone/rclone.sh
rclone config --config /home/rclone/rclone.conf
/home/rclone/rclone.sh start
