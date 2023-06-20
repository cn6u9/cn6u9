#!/bin/bash
function blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
function green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
function red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
function version_lt(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1"; 
}

source /etc/os-release
RELEASE=$ID
VERSION=$VERSION_ID
if [ "$RELEASE" == "centos" ] || [ "$RELEASE" == "almalinux" ]; then
    release="centos"
    systemPackage="yum"
    green 'dectect centos! systemPackage is yum'
elif [ "$RELEASE" == "debian" ] || [ "$RELEASE" == "ubuntu" ]; then
    release="debian"
    systemPackage="apt-get"
	green 'dectect centos! systemPackage is apt-get'
fi
systempwd="/etc/systemd/system/"

function install_trojan(){
    $systemPackage install -y nginx
    if [ ! -d "/etc/nginx/" ]; then
        red "nginx安装有问题，请使用卸载trojan-go后重新安装"
        exit 1
    fi
    cat > /etc/nginx/nginx.conf <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
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
        charset utf-8; 
    }
}
EOF
    systemctl restart nginx
    sleep 3
    rm -rf /usr/share/nginx/html/*
    cd /usr/share/nginx/html/
    wget https://github.com/cn6u9/cn6u9/raw/main/trojan/fakesite.zip
    unzip fakesite.zip
    sleep 5
    if [ ! -d "/usr/src" ]; then
        mkdir /usr/src
    fi
    if [ ! -d "/usr/src/trojan-cert" ]; then
        mkdir /usr/src/trojan-cert /usr/src/trojan-go-temp
        mkdir /usr/src/trojan-cert/$your_domain
        if [ ! -d "/usr/src/trojan-cert/$your_domain" ]; then
            red "不存在/usr/src/trojan-cert/$your_domain目录"
            exit 1
        fi
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --register-account  -m test@$your_domain --server zerossl
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --nginx
        if test -s /root/.acme.sh/$your_domain/fullchain.cer; then
            cert_success="1"
        fi
    elif [ -f "/usr/src/trojan-cert/$your_domain/fullchain.cer" ]; then
        cd /usr/src/trojan-cert/$your_domain
        create_time=`stat -c %Y fullchain.cer`
        now_time=`date +%s`
        minus=$(($now_time - $create_time ))
        if [  $minus -gt 5184000 ]; then
            curl https://get.acme.sh | sh
            ~/.acme.sh/acme.sh  --register-account  -m test@$your_domain --server zerossl
            ~/.acme.sh/acme.sh  --issue  -d $your_domain  --nginx
            if test -s /root/.acme.sh/$your_domain/fullchain.cer; then
                cert_success="1"
            fi
        else 
            green "检测到域名$your_domain证书存在且未超过60天，无需重新申请"
            cert_success="1"
        fi        
    else 
        mkdir /usr/src/trojan-cert/$your_domain
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --register-account  -m test@$your_domain --server zerossl
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --nginx
        if test -s /root/.acme.sh/$your_domain/fullchain.cer; then
            cert_success="1"
        fi
    fi
    
    if [ "$cert_success" == "1" ]; then
        cat > /etc/nginx/nginx.conf <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
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
        listen       127.0.0.1:80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
        charset utf-8; 
    }
    server {
        listen       0.0.0.0:80;
        server_name  $your_domain;
    
    location  /aria {
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
        }
        
    location  / {
            return 301 https://$your_domain\$request_uri;
            }
        
    }
    
}
EOF
        systemctl restart nginx
        systemctl enable nginx
        cd /usr/src
        wget https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest >/dev/null 2>&1
        latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
        rm -f latest
        green "开始下载最新版trojan-go amd64"
        wget https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip >/dev/null 2>&1
        unzip trojan-go-linux-amd64.zip -d trojan-go >/dev/null 2>&1
        rm -f trojan-go-linux-amd64.zip
        rm -rf ./trojan-go/example
        green "请设置trojan-go密码，建议不要出现特殊字符"
        read -p "请输入密码 :" trojan_passwd

        rm -rf /usr/src/trojan-go/server.json
        cat > /usr/src/trojan-go/server.json <<-EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 65444,
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
    "cert": "/usr/src/trojan-cert/$your_domain/fullchain.cer",
    "key": "/usr/src/trojan-cert/$your_domain/private.key",
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "",
    "fallback_port": 0,
    "fingerprint": ""
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
    "geoip": "/usr/src/trojan-go/geoip.dat",
    "geosite": "/usr/src/trojan-go/geosite.dat"
  },
  "websocket": {
    "enabled": false,
    "path": "",
    "host": ""
  },
  "mysql": {
    "enabled": false,
    "server_addr": "localhost",
    "server_port": 3306,
    "database": "",
    "username": "",
    "password": "",
    "check_rate": 60
  }
}
EOF
        rm -rf /usr/src/trojan-go-temp/
        cat > ${systempwd}trojan-go.service <<-EOF
[Unit]  
Description=trojan-go  
After=network.target  
   
[Service]  
Type=simple  
PIDFile=/usr/src/trojan-go/trojan-go/trojan-go.pid
ExecStart=/usr/src/trojan-go/trojan-go -config "/usr/src/trojan-go/server.json"  
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=1s
   
[Install]  
WantedBy=multi-user.target
EOF

        chmod +x ${systempwd}trojan-go.service
        systemctl enable trojan-go.service
        cd /root
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /usr/src/trojan-cert/$your_domain/private.key \
            --fullchain-file  /usr/src/trojan-cert/$your_domain/fullchain.cer \
            --reloadcmd  "systemctl restart trojan-go"    
        green "Trojan-Go安装成功！"
        showme_sub
    else
        red "==================================="
        red "https证书没有申请成功，本次安装失败"
        red "==================================="
    fi
}
function preinstall_check(){

    nginx_status=`ps -aux | grep "nginx: worker" |grep -v "grep"`
    if [ -n "$nginx_status" ]; then
        systemctl stop nginx
    fi
    $systemPackage -y install net-tools socat unzip >/dev/null 2>&1
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
    if [ -f "/etc/selinux/config" ]; then
        CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
        if [ "$CHECK" == "SELINUX=enforcing" ]; then
            green "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
            setenforce 0
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        elif [ "$CHECK" == "SELINUX=permissive" ]; then
            green "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
            setenforce 0
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
        fi
    fi
    if [ "$release" == "centos" ]; then
        firewall_status=`systemctl status firewalld | grep "Active: active"`
        if [ -n "$firewall_status" ]; then
            green "检测到firewalld开启状态，添加放行80/443端口规则"
            firewall-cmd --zone=public --add-port=80/tcp --permanent
            firewall-cmd --zone=public --add-port=443/tcp --permanent
            firewall-cmd --reload
        fi
    elif [ "$release" == "debian" ]; then
        ufw_status=`systemctl status ufw | grep "Active: active"`
        if [ -n "$ufw_status" ]; then
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw reload
        fi
        apt-get update
    elif [ "$release" == "debian" ]; then
        ufw_status=`systemctl status ufw | grep "Active: active"`
        if [ -n "$ufw_status" ]; then
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw reload
        fi
        apt-get update
    fi
    $systemPackage -y install  wget unzip zip curl tar >/dev/null 2>&1
    green "======================="
    blue "请输入绑定到本VPS的域名"
    green "======================="
    read your_domain
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        green "=========================================="
        green "       域名解析正常，开始安装trojan"
        green "=========================================="
        sleep 1s
        install_trojan
    else
        red "===================================="
        red "域名解析地址与本VPS IP地址不一致"
        red "若你确认解析成功你可强制脚本继续运行"
        red "===================================="
        read -p "是否强制运行 ?请输入 [Y/n] :" yn
        [ -z "${yn}" ] && yn="y"
        if [[ $yn == [Yy] ]]; then
            green "强制继续运行脚本"
            sleep 1s
            install_trojan
        else
            exit 1
        fi
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
    green "============================"
    blue "请输入绑定到本VPS的域名"
    blue "务必与之前失败使用的域名一致"
    green "============================"
    read your_domain
    real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=`curl ipv4.icanhazip.com`
    if [ $real_addr == $local_addr ] ; then
        ~/.acme.sh/acme.sh  --register-account  -m test@$your_domain --server zerossl
        ~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
            --key-file   /usr/src/trojan-cert/$your_domain/private.key \
            --fullchain-file /usr/src/trojan-cert/$your_domain/fullchain.cer \
            --reloadcmd  "systemctl restart trojan-go"
        if test -s /usr/src/trojan-cert/$your_domain/fullchain.cer; then
            green "证书申请成功"
            systemctl restart trojan-go
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

function remove_trojan(){
    red "================================"
    red "即将卸载trojan-go"
    red "同时卸载安装的nginx"
    red "================================"
    systemctl stop trojan-go
    systemctl disable trojan-go
    systemctl stop nginx
    systemctl disable nginx
    rm -f ${systempwd}trojan-go.service
    if [ "$RELEASE" == "centos" ] || [ "$RELEASE" == "almalinux" ]; then
        yum remove -y nginx
    else
        apt-get -y autoremove nginx
        apt-get -y --purge remove nginx
        apt-get -y autoremove && apt-get -y autoclean
        find / | grep nginx | sudo xargs rm -rf
    fi
    rm -rf /usr/src/trojan-go/
    rm -rf /usr/src/trojan-cert/
    rm -rf /usr/share/nginx/html/*
    rm -rf /etc/nginx/
    # rm -rf /root/.acme.sh/
    green "=============="
    green "trojan-go删除完毕"
    green "=============="
}

function update_trojan(){
    /usr/src/trojan-go/trojan-go -version >trojan-go.tmp
    curr_version=`cat trojan-go.tmp | grep "Trojan-Go" | awk '$2~/^v[0-9].*/{print substr($2,2)}'`
    wget https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest >/dev/null 2>&1
    latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
    rm -f latest
    rm -f trojan-go.tmp
    if version_lt "$curr_version" "$latest_version"; then
        green "当前版本$curr_version,最新版本$latest_version,开始升级……"
        mkdir trojan-go_update_temp && cd trojan-go_update_temp
        wget https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip
        unzip trojan-go-linux-amd64.zip -d trojan-go >/dev/null 2>&1
        rm -rf ./trojan-go/example
        mv -f ./trojan-go/* /usr/src/trojan-go/
        cd .. && rm -rf trojan-go_update_temp
        systemctl restart trojan-go
    /usr/src/trojan-go/trojan-go -version >trojan-go.tmp
    green "服务端trojan-go升级完成，当前版本：`cat trojan-go.tmp | grep "Trojan-Go" | awk '$2~/^v[0-9].*/{print substr($2,2)}'`，客户端请在trojan-go github下载最新版"
    rm -f trojan-go.tmp
    else
        green "当前版本$curr_version,最新版本$latest_version,无需升级"
    fi
    
}

function install_ss(){
    green "======================="
    blue "请输入SS服务端口"
    green "======================="
    read ss_port
    green "======================="
    blue "请输入SS密码"
    green "======================="
    read ss_password
    $systemPackage install net-tools -y
    wait
    PortSS=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w ${ss_port}`
    if [ -n "$PortSS" ]; then
        processSS=`netstat -tlpn | awk -F '[: ]+' -v port=$PortSS '$5==port{print $9}'`
        red "==========================================================="
        red "检测到$PortSS端口被占用，占用进程为：${processSS}，本次安装结束"
        red "==========================================================="
        exit 1
    fi
    if [ "$release" == "centos" ]; then
        firewall_status=`systemctl status firewalld | grep "Active: active"`
        if [ -n "$firewall_status" ]; then
            green "检测到firewalld开启状态，添加放行${ss_port}端口规则"
            firewall-cmd --zone=public --add-port=$ss_port/tcp --permanent
            firewall-cmd --reload
        fi
        $systemPackage install epel-release -y
        $systemPackage clean all
        $systemPackage makecache
        $systemPackage update -y
        $systemPackage install git gcc glibc-headers gettext autoconf libtool automake make pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel mbedtls-devel -y
    elif [ "$release" == "debian" ]; then
        ufw_status=`systemctl status ufw | grep "Active: active"`
        if [ -n "$ufw_status" ]; then
            ufw allow $ss_port/tcp
            ufw reload
        fi
        $systemPackage update -y
		$systemPackage install -y --no-install-recommends git libssl-dev gettext build-essential autoconf libtool libpcre3 libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev pkg-config
	fi
    if [ ! -d "/usr/src" ]; then
        mkdir /usr/src
    fi
    if [ ! -d "/usr/src/ss" ]; then
        mkdir /usr/src/ss
    fi
    cd /usr/src/ss
    git clone https://github.com/shadowsocks/shadowsocks-libev.git
    cd shadowsocks-libev
    git submodule update --init --recursive
    ./autogen.sh && ./configure && make
    make install
    if [ ! -d "/usr/src" ]; then
        mkdir /usr/src
    fi
    if [ ! -d "/usr/src/ss" ]; then
        mkdir /usr/src/ss
    fi
    rm -rf /usr/src/ss/ss-config
    cat > /usr/src/ss/ss-config <<-EOF
{
    "server": "0.0.0.0",
    "server_port": $ss_port,
    "local_port": 1080,
    "password": "$ss_password",
    "timeout": 600,
    "method": "chacha20-ietf-poly1305"
}
EOF
    cat > ${systempwd}ss.service <<-EOF
[Unit]  
Description=ShadowsSocks Server 
After=network.target  
   
[Service]  
Type=simple  
PIDFile=/usr/src/ss/ss.pid
ExecStart=nohup /usr/local/bin/ss-server -c /usr/src/ss/ss-config &  
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=1s
   
[Install]  
WantedBy=multi-user.target
EOF
    chmod +x ${systempwd}ss.service
    systemctl enable ss.service
    systemctl restart ss
}

function remove_ss(){
    red "================================"
    red "即将卸载ShadowsSocks....."
    red "为防止误卸载，之前安装的倚赖将不会被卸载，请自行决定是否卸载，例如git"
    red "================================"
    systemctl stop ss
    systemctl disable ss
    rm -f ${systempwd}ss.service
    cd /usr/src/ss/shadowsocks-libev
    make uninstall
    rm -rf /usr/src/ss/
    green "=============="
    green "ShadowSocks删除完毕"
    green "=============="
}

function showme_sub(){
    port=`cat /usr/src/trojan-go/server.json | grep local_port | awk -F '[,]+|[ ]' '{ print $(NF-1) }'`
    domain=`cat /usr/src/trojan-go/server.json | grep private.key | awk -F / '{ print $(NF-1) }'`
    password=`cat /usr/src/trojan-go/server.json | grep password | head -n 1 | awk -F '["]' '{ print $(NF-1) }'`
    green " ======================================="
    red "注意：下面仅仅是普通节点订阅链接，如使用clash等软件，请自行转换"
    green "你的Trojan订阅链接是：trojan://${password}@${domain}:${port}"
    green " ======================================="
}

start_menu(){
    # clear
    green " ======================================="
    green " 介绍: 一键安装trojan-go、ShadowSocks"
    green " 系统: centos7+/debian9+/ubuntu16.04+"
    red " 注意:"
    red " *1. 不要在任何生产环境使用此脚本"
    red " *2. 不要占用80和443端口"
    red " *3. 若第二次使用脚本安装，请先执行卸载"
    green " ======================================="
    echo
    green " 1. 安装trojan-go"
    red " 2. 卸载trojan-go"
    green " 3. 升级trojan-go"
    green " 4. 修复证书"
    green " 5. 安装ShadowSocks"
    red " 6. 卸载ShadowSocks"
    green " 7. 显示订阅链接"
    blue " 0. 退出脚本"
    echo
    read -p "请输入数字 :" num
    case "$num" in
    1)
    preinstall_check
    ;;
    2)
    remove_trojan 
    ;;
    3)
    update_trojan 
    ;;
    4)
    repair_cert 
    ;;
    5)
    install_ss 
    ;;
    6)
    remove_ss 
    ;;
    7)
    showme_sub 
    ;;
    0)
    exit 1
    ;;
    *)
    # clear
    red "请输入正确数字"
    sleep 1s
    start_menu
    ;;
    esac
}

start_menu
