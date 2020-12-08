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
    systemctl enable nginx
    systemctl stop nginx
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        green "=========================================="
        green "       域名解析正常，开始配置nginx以及更新证书"
        green "=========================================="
        sleep 1s
        cat > /etc/nginx/nginx.conf <<-EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid   /var/run/nginx.pid;
events {
worker_connections  1024;
}
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $your_domain trojan
        www.mb3admin.com web;
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
http {
    include      /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                                '\$status \$body_bytes_sent "\$http_referer" '
                                '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    server {
        listen       80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;    
    }
    #############################################
    server {
        #listen 80 default_server;
        listen 10240 ssl http2 default_server;
        server_name www.mb3admin.com mb3admin.com;
        index index.php index.html index.htm default.php default.htm default.html;
        root /usr/share/nginx/www.mb3admin.com;
        #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
        ssl_certificate    /usr/share/nginx/www.mb3admin.com/fullchain.pem;
        ssl_certificate_key    /usr/share/nginx/www.mb3admin.com/privkey.pem;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        error_page 497  https://\$host\$request_uri;
        #SSL-END
        #禁止访问的文件或目录
        location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md|fullchain.pem|privkey.pem) {
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
    ##############################################
}
EOF
        rm -rf /usr/share/nginx/www.mb3admin.com
        mkdir /usr/share/nginx/www.mb3admin.com
        cd /usr/share/nginx/www.mb3admin.com
        wget https://github.com/dzhl/script/raw/master/fullchain.pem
        wget https://github.com/dzhl/script/raw/master/privkey.pem
        sleep 5
        #申请https证书
        mkdir /usr/src/trojan-cert /usr/src/trojan-temp
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
        --key-file   /usr/src/trojan-cert/private.key \
        --fullchain-file /usr/src/trojan-cert/fullchain.cer
        if test -s /usr/src/trojan-cert/fullchain.cer; then
            systemctl start nginx
        else
            red "==================================="
            red "https证书没有申请成果，自动安装失败"
            green "不要担心，你可以手动修复证书申请"
            green "1. 重启VPS"
            green "2. 重新执行脚本，使用修复证书功能"
            red "==================================="
        fi
    else
    	red "================================"
    	red "域名解析地址与本VPS IP地址不一致"
    	red "本次安装失败，请确保域名解析正常"
    	red "================================"
    fi
}
function install_trojan(){
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        green "=========================================="
        green "       域名解析正常，开始安装trojan"
        green "=========================================="
        sleep 1s
        cd /usr/src
        if [ $1 == 1 ] ; then
        green "======================="
        blue "打开https://github.com/p4gefau1t/trojan-go/releases，最新版本号，输入版本号，不需要输入v"
        green "======================="
        read latest_version
        #wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest
        #latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
        wget https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip
        #tar xf trojan-${latest_version}-linux-amd64.tar.xz
        unzip trojan-go-linux-amd64.zip -d trojan
        rm trojan-go-linux-amd64.zip
        cd ./trojan
        mv ./trojan-go ./trojan
        
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
        rm -rf /usr/src/trojan/config.json
        cat > /usr/src/trojan/config.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10241,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "log_level": 1,
    "log_file": "",
    "password": ["$trojan_passwd"],
    "disable_http_check": false,
    "udp_timeout": 60,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "/usr/src/trojan-cert/fullchain.cer",
        "key": "/usr/src/trojan-cert/private.key",
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
        "geoip": "/usr/src/trojan/geoip.dat",
        "geosite": "/usr/src/trojan/geosite.dat"
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
ExecStart=/usr/src/trojan/trojan --config "/usr/src/trojan/config.json"    
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
        green "配置文件路径:/usr/src/trojan/config.json，修改后通过systemctl restart trojan使其生效"
        green "======================================================================"
    else
        red "==================================="
        red "Ip和域名不一致"
        green "不要担心，你可以手动修复证书申请"
        green "1. 重启VPS"
        green "2. 重新执行脚本，使用修复证书功能"
        red "==================================="
    fi
}
function repair_cert(){
    systemctl stop nginx
    Port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
    if [ -n "$Port80" ]; then
        process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
        red "==========================================================="
        red "检测到80端口被占用，占用进程为：${process80}，本次安装结束"
        red "==========================================================="
        exit 1
    fi
    green "======================="
    blue "请输入绑定到本VPS的域名"
    blue "务必与之前失败使用的域名一致"
    green "======================="
    read your_domain
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /usr/src/trojan-cert/private.key \
            --fullchain-file /usr/src/trojan-cert/fullchain.cer
        if test -s /usr/src/trojan-cert/fullchain.cer; then
            green "证书申请成功"
    	systemctl restart trojan
    	systemctl start nginx
        else
        	red "申请证书失败"
        fi
    else
        red "================================"
        red "域名解析地址与本VPS IP地址不一致"
        red "本次安装失败，请确保域名解析正常"
        red "================================"
    fi	
}
function remove_nginx(){
    red "================================"
    red "即将卸载nginx,同时卸载trojan"
    red "================================"
    rm -f ${systempwd}trojan.service
    systemctl stop nginx
    if [ "$release" == "centos" ]; then
        yum remove -y nginx
    else
        apt-get autoremove -y nginx
        apt-get  -y --purge remove libnginx-*
        apt-get  -y --purge remove nginx-*
        apt-get  -y --purge autoremove
    fi
    rm -rf /usr/share/nginx
    rm -rf /etc/nginx
    green "=============="
    green "nginx删除完毕"
    green "=============="
    remove_trojan
}
function remove_trojan(){
    red "================================"
    red "即将卸载trojan或者trojan-go"
    red "================================"
    systemctl stop trojan
    systemctl disable trojan
    rm -f ${systempwd}trojan.service
    rm -rf /usr/src/trojan
    green "=============="
    green "trojan或者trojan-go删除完毕"
    green "=============="
}

function bbr_boost_sh(){
    wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}
function install_PHPAndTypecho(){
    systemctl stop nginx
    green "=============="
    green "开始安装php相关"
    green "=============="
    $systemPackage -y install php7.2-fpm  php7.2-xml php7.2-xmlrpc php7.2-sqlite3 php7.2-mbstring php-memcached php7.2-curl php7.2-gd
    cat > /etc/nginx/nginx.conf <<-EOF
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid    /var/run/nginx.pid;
events {
    worker_connections  1024;
}
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $your_domain trojan;
        www.mb3admin.com web;
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
http {
    include    /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                                '\$status \$body_bytes_sent "\$http_referer" '
                                '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    sendfile      on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    server {
        listen     80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
        #typecho所需配置
        if (!-e \$request_filename) {
            rewrite ^(.*)\$ /index.php\$1 last;
        }
        location ~  .*\.php(\/.*)*\$ {
            #支持pathinfo的关键配置
            fastcgi_split_path_info ^(.+?\.php)(/.*)\$;
            #php-fpm的监听端口
            fastcgi_pass unix:/var/run/php/php7.2-fpm.sock; 
            fastcgi_index  index.php;
            fastcgi_param  SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
            include        fastcgi_params;
        }    
    }
    #############################################
    server {
        #listen 80 default_server;
        listen 10240 ssl http2 default_server;
        server_name www.mb3admin.com mb3admin.com;
        index index.php index.html index.htm default.php default.htm default.html;
        root /usr/share/nginx/www.mb3admin.com;
        #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
        ssl_certificate    /usr/share/nginx/www.mb3admin.com/fullchain.pem;
        ssl_certificate_key    /usr/share/nginx/www.mb3admin.com/privkey.pem;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        error_page 497  https://\$host\$request_uri;
        #SSL-END
        #禁止访问的文件或目录
        location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md|fullchain.pem|privkey.pem) {
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
    ##############################################
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
     green "安装php相关完毕，开始下载typecho"
     green "=============="
     systemctl start nginx
     systemctl start php7.2-fpm.service
     systemctl enable php7.2-fpm.service
     #设置伪装站
     rm -rf /usr/share/nginx/html/*
     cd /usr/share/nginx/html/
     wget https://github.com/dzhl/script/raw/master/typecho-1.1-17.10.30-release.zip
     unzip typecho-1.1-17.10.30-release.zip > /dev/null 2>&1
     green "=============="
     green "安下载typecho完毕"
     green "=============="
}
function remove_PHPAndTypecho(){
    red "================================"
    red "即将卸载php和Typecho"
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
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid   /var/run/nginx.pid;
events {
worker_connections  1024;
}
# 流量转发核心配置
stream {
    # 这里就是 SNI 识别，将域名映射成一个配置名
    map \$ssl_preread_server_name \$backend_name {
        $your_domain trojan
        www.mb3admin.com web;
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
http {
    include      /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                                '\$status \$body_bytes_sent "\$http_referer" '
                                '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    server {
        listen       80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;    
    }
    #############################################
    server {
        #listen 80 default_server;
        listen 10240 ssl http2 default_server;
        server_name www.mb3admin.com mb3admin.com;
        index index.php index.html index.htm default.php default.htm default.html;
        root /usr/share/nginx/www.mb3admin.com;
        #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
        ssl_certificate    /usr/share/nginx/www.mb3admin.com/fullchain.pem;
        ssl_certificate_key    /usr/share/nginx/www.mb3admin.com/privkey.pem;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        error_page 497  https://\$host\$request_uri;
        #SSL-END
        #禁止访问的文件或目录
        location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md|fullchain.pem|privkey.pem) {
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
    ##############################################
}
EOF
    rm -rf /usr/share/nginx/html/*
    green "=============="
    green "php和Typecho删除完毕"
    green "=============="
}
function testSpeed() {
    wget vpstest.cn/it && bash it
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
    green " 5. 卸载trojan"
    red " 6. 修复证书"
    green " 7. 安装BBR-PLUS加速4合一脚本"
    red " 8. 安装PHP和Typecho"
    green " 9. 卸载PHP和Typecho"
    red " 10. 一键安装nginx、Trojan-go、PHP、Typecho"
    green " 11. 一键安装nginx、Trojan、PHP、Typecho"
    red " 12. 一键卸载nginx、Trojan或者Trojan-go、PHP、Typecho"
    red " 13. 测速"
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
        repair_cert 
        ;;
    7)
        bbr_boost_sh 
        ;;
    8)
        install_PHPAndTypecho 
        ;;
    9)
        remove_PHPAndTypecho
        red "需要重启才能重新安装PHP,请手工重启"
        ;;
    10)
        install_nginx
        install_trojan 1
        install_PHPAndTypecho
        ;;
    11)
        install_nginx
        install_trojan 2
        install_PHPAndTypecho
        ;;
    12)
        remove_nginx
        remove_PHPAndTypecho
        red "需要重启才能重新安装,请手工重启"
        ;;
    13)
        testSpeed
        ;;
    0)
        exit 1
        ;;
    *)
    clear
    red "请输入正确数字"
    sleep 1s
    ;;
    esac
    start_menu
}
green "======================="
blue "请输入绑定到本VPS的域名"
green "======================="
read your_domain
start_menu