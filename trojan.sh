#!/bin/bash
#字体颜色
blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
#copy from 秋水逸冰 ss scripts
if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
fi

function install_nginx(){
    systemctl stop nginx
    $systemPackage -y install net-tools socat
    Port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
    Port443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`
    if [ -n "$Port80" ]; then
        process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
        red "==========================================================="
        red "检测到80端口被占用，占用进程为：${process80}，本次安装结束"
        red "==========================================================="
        exit 1
    fi
    if [ -n "$Port443" ]; then
        process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
        red "============================================================="
        red "检测到443端口被占用，占用进程为：${process443}，本次安装结束"
        red "============================================================="
        exit 1
    fi
    CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$CHECK" == "SELINUX=enforcing" ]; then
        red "======================================================================="
        red "检测到SELinux为开启状态，为防止申请证书失败，请先重启VPS后，再执行本脚本"
        red "======================================================================="
        read -p "是否现在重启 ?请输入 [Y/n] :" yn
        [ -z "${yn}" ] && yn="y"
        if [[ $yn == [Yy] ]]; then
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
                setenforce 0
            echo -e "VPS 重启中..."
            reboot
        fi
        exit
    fi
    if [ "$CHECK" == "SELINUX=permissive" ]; then
        red "======================================================================="
        red "检测到SELinux为宽容状态，为防止申请证书失败，请先重启VPS后，再执行本脚本"
        red "======================================================================="
        read -p "是否现在重启 ?请输入 [Y/n] :" yn
        [ -z "${yn}" ] && yn="y"
        if [[ $yn == [Yy] ]]; then
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
                setenforce 0
            echo -e "VPS 重启中..."
            reboot
        fi
        exit
    fi
    if [ "$release" == "centos" ]; then
        if  [ -n "$(grep ' 6\.' /etc/redhat-release)" ] ;then
        red "==============="
        red "当前系统不受支持"
        red "==============="
        exit
        fi
        if  [ -n "$(grep ' 5\.' /etc/redhat-release)" ] ;then
        red "==============="
        red "当前系统不受支持"
        red "==============="
        exit
        fi
        systemctl stop firewalld
        systemctl disable firewalld
        rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
    elif [ "$release" == "ubuntu" ]; then
        if  [ -n "$(grep ' 14\.' /etc/os-release)" ] ;then
        red "==============="
        red "当前系统不受支持"
        red "==============="
        exit
        fi
        if  [ -n "$(grep ' 12\.' /etc/os-release)" ] ;then
        red "==============="
        red "当前系统不受支持"
        red "==============="
        exit
        fi
        systemctl stop ufw
        systemctl disable ufw
        apt-get update
    elif [ "$release" == "debian" ]; then
        apt-get update
    fi
    $systemPackage -y install  nginx wget unzip zip curl tar
systemctl eneable nginx
    systemctl stop nginx
    mkdir /etc/nginx/vhost
    mkdir /etc/nginx/ssl
    mkdir /home/wwwroot
    mkdir /home/wwwlogs
    mkdir /home/wwwroot/default
    cd /etc/nginx
    wget https://github.com/dzhl/script/raw/master/nginxconf.zip
    unzip nginxconf.zip > /dev/null 2>&1
    rm nginxconf.zip
    cd  /root
    cat > /etc/nginx/nginx.conf <<-EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user  root;
worker_processes auto;
worker_cpu_affinity auto;
error_log  /home/wwwlogs/nginx_error.log  crit;
pid        /var/run/nginx.pid;
#Specifies the value for maximum file descriptors that can be opened by this process.
#worker_rlimit_nofile 51200;
events
    {
        use epoll;
        #worker_connections 51200;
        multi_accept off;
        accept_mutex off;
    }
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $trojan_domain trojan;
        # 域名都不匹配情况下的默认值
        default web;
    }
    
    # web，配置转发详情
    upstream web {
        server 127.0.0.1:10240;
    }
    
    # trojan，配置转发详情
    upstream trojan {
        server 127.0.0.1:10241;
    }
    # 监听 443 并开启 ssl_preread
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_pass  \$backend_name;
        ssl_preread on;
    }
}
http
    {
        include       mime.types;
        default_type  application/octet-stream;
        server_names_hash_bucket_size 128;
        client_header_buffer_size 32k;
        large_client_header_buffers 4 32k;
        client_max_body_size 50m;
        sendfile on;
        sendfile_max_chunk 512k;
        tcp_nopush on;
        keepalive_timeout 60;
        tcp_nodelay on;
        gzip on;
        gzip_min_length  1k;
        gzip_buffers     4 16k;
        gzip_http_version 1.1;
        gzip_comp_level 2;
        gzip_types     text/plain application/javascript application/x-javascript text/javascript text/css application/xml application/xml+rss;
        gzip_vary on;
        gzip_proxied   expired no-cache no-store private auth;
        gzip_disable   "MSIE [1-6]\.";
        #limit_conn_zone $binary_remote_addr zone=perip:10m;
        ##If enable limit_conn_zone,add "limit_conn perip 10;" to server section.
        server_tokens off;
        access_log off;
server
    {
        listen 80 default_server reuseport;
        #listen [::]:80 default_server ipv6only=on;
        server_name _;
        index index.html index.htm index.php;
        root  /home/wwwroot/default;
        #error_page   404   /404.html;
        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php\$ { deny all; }
        #include enable-php.conf;
        location /nginx_status
        {
            stub_status on;
            access_log   off;
        }
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }
        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        location ~ /.well-known {
            allow all;
        }
        location ~ /\.
        {
            deny all;
        }
        access_log  /home/wwwlogs/access.log;
    }
include vhost/*.conf;
}
EOF
    systemctl start nginx
}
function create_embyserver(){
    delete_embyserver
    mkdir /home/wwwroot/www.mb3admin.com
    cd /home/wwwroot/www.mb3admin.com
    wget https://github.com/dzhl/script/raw/master/fullchain.cer
    wget https://github.com/dzhl/script/raw/master/private.key
    cat > /etc/nginx/vhost/www.mb3admin.com.conf <<-EOF
server {
        #listen 80 default_server;
        listen 10240 ssl http2 default_server;
        server_name www.mb3admin.com mb3admin.com;
        index index.php index.html index.htm default.php default.htm default.html;
        root /home/wwwroot/www.mb3admin.com;
        #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
        ssl_certificate    /home/wwwroot/www.mb3admin.com/fullchain.cer;
        ssl_certificate_key    /home/wwwroot/www.mb3admin.com/private.key;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        error_page 497  https://\$host\$request_uri;
        #SSL-END
        #禁止访问的文件或目录
        location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md|fullchain.cer|private.key) {
            return 404;
        }
        
        location /admin/service/registration/validateDevice {    
           default_type application/json;  return 200 '{"cacheExpirationDays": 7,"message": "Device Valid","resultCode": "GOOD"}';
         }
        location /admin/service/registration/validate {    
            default_type application/json;  return 200 '{"featId":"","registered":true,"expDate":"2099-01-01","key":""}';
        }
        location /admin/service/registration/getStatus {    
           default_type application/json;  return 200 '{"deviceStatus":"","planType":"","subscriptions":{}}';
        }
        access_log  '';
        error_log  '';
        add_header Access-Control-Allow-Origin *; 
        add_header Access-Control-Allow-Headers *;  
        add_header Access-Control-Allow-Method *;  
        add_header Access-Control-Allow-Credentials true;
    }
EOF
    systemctl restart nginx
}
function delete_embyserver(){
    rm -rf /home/wwwroot/www.mb3admin.com
    systemctl stop nginx
    rm -rf /etc/nginx/ssl/www.mb3admin.com
    rm -rf /etc/nginx/vhost/www.mb3admin.com.conf
    systemctl start nginx
}
function install_trojan(){
    your_domain=trojan_domain
    create_cert
    sleep 1s
    rm -rf /etc/trojan
             cd  /etc
    if [ $1 == 1 ] ; then
        green "======================="
        blue "打开https://github.com/p4gefau1t/trojan-go/releases，最新版本号，输入版本号，不需要输入v"
        green "======================="
        read latest_version
        wget https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip
        unzip trojan-go-linux-amd64.zip -d trojan
        rm trojan-go-linux-amd64.zip
        mv ./trojan/trojan-go ./trojan/trojan
    else
        wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest
        latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
        wget https://github.com/trojan-gfw/trojan/releases/download/v${latest_version}/trojan-${latest_version}-linux-amd64.tar.xz
        tar xf trojan-1.16.0-linux-amd64.tar.xz
        rm trojan-${latest_version}-linux-amd64.tar.xz
    fi

    #设定trojan密码
    green "======================="
    blue "请输入密码"
    green "======================="
    read trojan_passwd
    #trojan_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
    #配置trojan
    rm -rf /etc/trojan/config.json
    cat > /etc/trojan/config.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10241,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "log_level": 3,
    "log_file": "",
    "password": ["$trojan_passwd"],
    "disable_http_check": false,
    "udp_timeout": 60,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "/etc/nginx/ssl/$your_domain/fullchain.cer",
        "key": "/etc/nginx/ssl/$your_domain/private.key",
        "key_password": "",
        "cipher": "",
        "curves": "",
        "prefer_server_cipher": false,
        "sni": "$your_domain",
        "alpn": [
            "http/1.1"
        ],
        "session_ticket": true,
        "reuse_session": true,
        "plain_http_response": "",
        "fallback_addr": "",
        "fallback_port": 0,
        "fingerprint": "firefox"
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "prefer_ipv4": false
    },
    "mux": {
        "enabled": false,
        "concurrency": 8,
        "idle_timeout": 60
    },
    "router": {
        "enabled": false,
        "bypass": [],
        "proxy": [],
        "block": [],
        "default_policy": "proxy",
        "domain_strategy": "as_is",
        "geoip": "/etc/trojan/geoip.dat",
        "geosite": "/etc/trojan/geosite.dat"
    },
    "websocket": {
        "enabled": false,
        "path": "",
        "host": ""
    },
    "shadowsocks": {
        "enabled": false,
        "method": "AES-128-GCM",
        "password": ""
    },
    "transport_plugin": {
        "enabled": false,
        "type": "",
        "command": "",
        "option": "",
        "arg": [],
        "env": []
    },
    "forward_proxy": {
        "enabled": false,
        "proxy_addr": "",
        "proxy_port": 0,
        "username": "",
        "password": ""
    },
    "mysql": {
        "enabled": false,
        "server_addr": "localhost",
        "server_port": 3306,
        "database": "",
        "username": "",
        "password": "",
        "check_rate": 60
    },
    "api": {
        "enabled": false,
        "api_addr": "",
        "api_port": 0,
        "ssl": {
            "enabled": false,
            "key": "",
            "cert": "",
            "verify_client": false,
            "client_cert": []
        }
    }
}
EOF
#增加启动脚本
cat > ${systempwd}trojan.service <<-EOF
[Unit]  
Description=trojan
After=network.target nss-lookup.target 
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true  
ExecStart=/etc/trojan/trojan --config "/etc/trojan/config.json"    
Restart=on-failure
RestartSec=10s  
[Install]  
WantedBy=multi-user.target
EOF
    chmod +x ${systempwd}trojan.service
    systemctl start trojan.service
    systemctl enable trojan.service
    green "======================================================================"
    green "Trojan已安装完成，参数如下:"
    green "域名:$your_domain"
    green "端口:443"
    green "密码:$trojan_passwd"
    green "链接:trojan://$trojan_passwd@$your_domain:443"
    green "配置文件路径:/etc/trojan/config.json，修改后通过systemctl restart trojan使其生效"
    green "======================================================================"

}
function create_cert(){
    systemctl stop nginx
    Port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
    if [ -n "$Port80" ]; then
        process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
        red "==========================================================="
        red "检测到80端口被占用，占用进程为：${process80}，本次安装结束"
        red "==========================================================="
        exit 1
    fi
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        mkdir /etc/nginx/ssl/$your_domain
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /etc/nginx/ssl/$your_domain/private.key \
            --fullchain-file /etc/nginx/ssl/$your_domain/fullchain.cer
        if test -s /etc/nginx/ssl/$your_domain/fullchain.cer; then
            green "证书申请成功"
        systemctl start nginx
        else
            red "申请证书失败"
            systemctl start nginx
            exit
        fi
    else
        red "================================"
        red "域名解析地址与本VPS IP地址不一致"
        red "本次安装失败，请确保域名解析正常"
        red "================================"
        systemctl start nginx
        exit
    fi    
}
function remove_nginx(){
    red "================================"
    red "开始卸载nginx"
    red "================================"
    rm -f ${systempwd}trojan.service
    systemctl stop nginx
    systemctl stop trojan
    if [ "$release" == "centos" ]; then
        yum remove -y nginx
    else
        apt-get autoremove -y nginx
        apt-get  -y --purge remove libnginx-*
        apt-get  -y --purge remove nginx-*
        apt-get  -y --purge autoremove
    fi
    rm -rf /etc/nginx
    green "=============="
    green "nginx删除完毕"
    green "=============="
}
function remove_trojan(){
    red "================================"
    red "即将卸载trojan或者trojan-go"
    red "================================"
    systemctl stop trojan
    systemctl disable trojan
    rm -f ${systempwd}trojan.service
    rm -rf /etc/trojan
    green "=============="
    green "trojan或者trojan-go删除完毕"
    green "=============="
}
function remove_allsitesfiles(){
    rm -rf /home/wwwroots
    rm -rf /home/wwwlogs
}
function bbr_boost_sh(){
    wget -N --no-check-certificate  "https://github.000060000.xyz/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}
function install_typecho(){
     addSite
     cd /home/wwwroot/$your_domain
     wget https://github.com/dzhl/script/raw/master/typecho.zip
     unzip typecho.zip > /dev/null 2>&1
     wget https://github.com/BadApple9/speedtest-x/archive/master.zip
     unzip master.zip > /dev/null 2>&1
     mv speedtest-x-master speedtest
     rm typecho.zip
     rm master.zip
     green "=============="
     green "安下载typecho完毕"
     green "=============="
     cd /root
}
function install_php(){
    systemctl stop nginx
    green "=============="
    green "开始安装php相关"
    green "=============="
    $systemPackage -y install php7.2-fpm  php7.2-xml php7.2-xmlrpc php7.2-sqlite3 php7.2-mbstring php-memcached php7.2-curl php7.2-gd php7.2-zip
    cat > /etc/nginx/nginx.conf <<-EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user  root;
worker_processes auto;
worker_cpu_affinity auto;
error_log  /home/wwwlogs/nginx_error.log  crit;
pid        /var/run/nginx.pid;
#Specifies the value for maximum file descriptors that can be opened by this process.
#worker_rlimit_nofile 51200;
events
    {
        use epoll;
        #worker_connections 51200;
        multi_accept off;
        accept_mutex off;
    }
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $trojan_domain trojan;
        # 域名都不匹配情况下的默认值
        default web;
    }
    
    # web，配置转发详情
    upstream web {
        server 127.0.0.1:10240;
    }
    
    # trojan，配置转发详情
    upstream trojan {
        server 127.0.0.1:10241;
    }
    # 监听 443 并开启 ssl_preread
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_pass  \$backend_name;
        ssl_preread on;
    }
}
http
    {
        include       mime.types;
        default_type  application/octet-stream;
        server_names_hash_bucket_size 128;
        client_header_buffer_size 32k;
        large_client_header_buffers 4 32k;
        client_max_body_size 50m;
        sendfile on;
        sendfile_max_chunk 512k;
        tcp_nopush on;
        keepalive_timeout 60;
        tcp_nodelay on;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 64k;
        fastcgi_buffers 4 64k;
        fastcgi_busy_buffers_size 128k;
        fastcgi_temp_file_write_size 256k;
        gzip on;
        gzip_min_length  1k;
        gzip_buffers     4 16k;
        gzip_http_version 1.1;
        gzip_comp_level 2;
        gzip_types     text/plain application/javascript application/x-javascript text/javascript text/css application/xml application/xml+rss;
        gzip_vary on;
        gzip_proxied   expired no-cache no-store private auth;
        gzip_disable   "MSIE [1-6]\.";
        #limit_conn_zone $binary_remote_addr zone=perip:10m;
        ##If enable limit_conn_zone,add "limit_conn perip 10;" to server section.
        server_tokens off;
        access_log off;
server
    {
        listen 80 default_server reuseport;
        #listen [::]:80 default_server ipv6only=on;
        server_name _;
        index index.html index.htm index.php;
        root  /home/wwwroot/default;
        #error_page   404   /404.html;
        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php\$ { deny all; }
        #include enable-php.conf;
        location /nginx_status
        {
            stub_status on;
            access_log   off;
        }
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }
        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        location ~ /.well-known {
            allow all;
        }
        location ~ /\.
        {
            deny all;
        }
        access_log  /home/wwwlogs/access.log;
    }
include vhost/*.conf;
}
EOF
     cat > ${systempwd}php7.2-fpm.service <<-EOF
[Unit]
Description=The PHP 7.2 FastCGI Process Manager
Documentation=man:php-fpm7.2(8)
After=network.target
[Service] 
Type=simple
PIDFile=/run/php/php7.2-fpm.pid
ExecStart=/usr/sbin/php-fpm7.2  --nodaemonize --fpm-config /etc/php/7.2/fpm/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
[Install]
WantedBy=multi-user.target
EOF
     green "=============="
     green "安装php相关完毕"
     green "=============="
     systemctl start nginx
     systemctl start php7.2-fpm.service
     systemctl enable php7.2-fpm.service
  
}
function remove_php(){
    red "================================"
    red "开始卸载php"
    red "================================"
    systemctl stop php7.2-fpm
    systemctl disable php7.2-fpm
    rm -f ${systempwd}php7.2-fpm.service
    if [ "$release" == "centos" ]; then
        yum remove -y php7.2-*
    else
    apt autoremove -y php7.2-*
    fi
    cat > /etc/nginx/nginx.conf <<-EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user  root;
worker_processes auto;
worker_cpu_affinity auto;
error_log  /home/wwwlogs/nginx_error.log  crit;
pid        /var/run/nginx.pid;
#Specifies the value for maximum file descriptors that can be opened by this process.
#worker_rlimit_nofile 51200;
events
    {
        use epoll;
        #worker_connections 51200;
        multi_accept off;
        accept_mutex off;
    }
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $trojan_domain trojan;
        # 域名都不匹配情况下的默认值
        default web;
    }
    
    # web，配置转发详情
    upstream web {
        server 127.0.0.1:10240;
    }
    
    # trojan，配置转发详情
    upstream trojan {
        server 127.0.0.1:10241;
    }
    # 监听 443 并开启 ssl_preread
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_pass  \$backend_name;
        ssl_preread on;
    }
}
http
    {
        include       mime.types;
        default_type  application/octet-stream;
        server_names_hash_bucket_size 128;
        client_header_buffer_size 32k;
        large_client_header_buffers 4 32k;
        client_max_body_size 50m;
        sendfile on;
        sendfile_max_chunk 512k;
        tcp_nopush on;
        keepalive_timeout 60;
        tcp_nodelay on;
        gzip on;
        gzip_min_length  1k;
        gzip_buffers     4 16k;
        gzip_http_version 1.1;
        gzip_comp_level 2;
        gzip_types     text/plain application/javascript application/x-javascript text/javascript text/css application/xml application/xml+rss;
        gzip_vary on;
        gzip_proxied   expired no-cache no-store private auth;
        gzip_disable   "MSIE [1-6]\.";
        #limit_conn_zone $binary_remote_addr zone=perip:10m;
        ##If enable limit_conn_zone,add "limit_conn perip 10;" to server section.
        server_tokens off;
        access_log off;
server
    {
        listen 80 default_server reuseport;
        #listen [::]:80 default_server ipv6only=on;
        server_name _;
        index index.html index.htm index.php;
        root  /home/wwwroot/default;
        #error_page   404   /404.html;
        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php\$ { deny all; }
        #include enable-php.conf;
        location /nginx_status
        {
            stub_status on;
            access_log   off;
        }
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }
        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        location ~ /.well-known {
            allow all;
        }
        location ~ /\.
        {
            deny all;
        }
        access_log  /home/wwwlogs/access.log;
    }
include vhost/*.conf;
EOF
    green "=============="
    green "php删除完毕"
    green "=============="
}
function addSite() {
    green "======================="
    blue "请输入绑定到本VPS的站点域名"
    green "======================="
    read your_domain
    create_cert
    systemctl stop nginx
    rm -rf /home/wwwroot/$your_domain
    rm /etc/nginx/vhost/$your_domain.conf
    mkdir /home/wwwroot/$your_domain
    cat > /etc/nginx/vhost/$your_domain.conf <<-EOF
server
    {
        listen 10240 ssl http2;
        #listen [::]:443 ssl http2;
        server_name $your_domain;
        index index.html index.htm index.php default.html default.htm default.php;
        root  /home/wwwroot/$your_domain;
        ssl_certificate /etc/nginx/ssl/$your_domain/fullchain.cer;
        ssl_certificate_key /etc/nginx/ssl/$your_domain/private.key;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers "TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        #ssl_dhparam /etc/nginx/ssl/dhparam.pem;
        include rewrite/typecho.conf;
        #error_page   404   /404.html;
        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }
        include enable-php-pathinfo.conf;
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }
        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }
        location ~ /.well-known {
            allow all;
        }
        location ~ /\.
        {
            deny all;
        }
        access_log off;
    }
EOF
    systemctl start nginx
}
function removeSite() {
    green "======================="
    blue "请输入绑定到本VPS的站名"
    green "======================="
    read your_domain
    systemctl stop nginx
    rm -rf /home/wwwroot/$your_domain
    rm -rf /etc/nginx/ssl/$your_domain
    rm /etc/nginx/vhost/$your_domain.conf
    systemctl start nginx
}
function testSpeed() {
    wget vpstest.cn/it && bash it
}
function pagetestSpeed() {
    wget -N --no-check-certificate "https://raw.githubusercontent.com/dzhl/script/master/speedtest" && chmod +x speedtest && ./speedtest
}
start_menu(){
    green " ===================================="
    green " Trojan 一键安装自动脚本 2020-2-27 更新      "
    green " 系统：centos7+/debian9+/ubuntu16.04+"
    blue " 声明："
    red " *请不要在任何生产环境使用此脚本"
    red " *请不要有其他程序占用80和443端口"
    red " *若是第二次使用脚本，请先执行卸载trojan"
    green " ======================================="
    echo
    green " 1. 安装Nginx"
    red " 2. 卸载Nginx"
    green " 3. 安装trojan-go"
    red " 4. 安装trojan"
    green " 5. 卸载trojan/trojan-go"
    red " 6. 一键安装Nginx、trojan-go"
    green " 7. 一键安装Nginx、trojan"
    red " 8. 修复证书"
    green " 9. 安装php"
    red " 10. 卸载PHP"
    green " 11. 添加Typecho"
    red " 12. 添加站点"
    green " 13. 删除站点"
    red " 14. 清除所有站点文件"
    green " 15. 一键安装PHP、Typecho、speedtest"
    red " 16. 一键卸载PHP、Typecho、speedtest"
    green " 17. 一键安装nginx、Trojan-go、PHP、Typecho、speedtest"
    red " 18. 一键安装nginx、Trojan、PHP、Typecho、speedtest"
    green " 19. 一键卸载nginx、Trojan或者Trojan-go、PHP、Typecho"
    red " 20. 测速"
    green " 21. 单文件版测速"
    red " 22. 安装BBR-PLUS加速4合一脚本"
    green " 23. 创建emb3admin.com伪站点"
    red " 24. 删除emb3admin.com伪站点"
    blue " 0. 退出脚本"
    echo
    read -p "请输入数字:" num
    case "$num" in
    1)
        install_nginx
        ;;
    2)
        remove_nginx
        red "需要重启才能重新安装nginx,请手工重启"
        ;;
    3)
        install_trojan 1
        ;;
    4)
        install_trojan 2
        ;;
    5)
        remove_trojan
        ;;
    6)
        install_nginx
    install_trojan 1
        ;;
    7)
        install_nginx
    install_trojan 2
        ;;
    8)
        green "======================="
        blue "请输入绑定到本VPS的站点或Trojan域名"
        green "======================="
        read your_domain
        create_cert 
        ;;
    9)
        install_php
        ;;
    10)
        remove_php
        red "需要重启才能重新安装PHP,请手工重启"
        ;;
    11)
        install_typecho
        ;;
    12)
        addSite
        ;;
    13)
        removeSite
        ;;
    14)
        remove_allsitesfiles
        ;;
    15)
        install_php 
        install_typecho
        ;;
    16)
        removeSite 
        remove_php
        ;;
    17)
        install_nginx
        install_trojan 1
        install_php
        install_typecho
        ;;
    18)
        install_nginx
        install_trojan 2
        install_php
        install_typecho
        ;;
    19)
        remove_trojan
        removeSite
        remove_php
        remove_nginx
        red "需要重启才能重新安装,请手工重启"
        ;;
    20)
        pagetestSpeed
        ;;
    21)
        testSpeed
        ;;
    22)
        bbr_boost_sh
        ;;
    23)
        create_embyserver
        ;;
    24)
        delete_embyserver
        ;;
    0)
        exit 1
        ;;
    *)
    red "请输入正确数字"
    sleep 1s
    ;;
    esac
    start_menu
}
green "======================="
blue "如需安装trojan，请输入绑定到本VPS的trojan域名"
green "======================="
read trojan_domain
if [ "" = "$trojan_domain" ] ;then
    trojan_domain="none"
start_menu
