#!/bin/bash

blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
version_lt(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1"; 
}

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
function install(){
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
    }
}
EOF
	#设置伪装站
	rm -rf /usr/share/nginx/html/*
	cd /usr/share/nginx/html/
	wget https://github.com/cn6u9/cn6u9/raw/main/trojan/web.zip >/dev/null 2>&1
    	unzip web.zip >/dev/null 2>&1
	systemctl stop nginx
	sleep 5
	#申请https证书
	if [ ! -d "/usr/src" ]; then
	    mkdir /usr/src
	fi
	mkdir /usr/src/trojan-cert /usr/src/trojan-temp
	curl https://get.acme.sh | sh
	~/.acme.sh/acme.sh  --issue  -d $your_domain  --standalone
    	~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
        --key-file   /usr/src/trojan-cert/private.key \
        --fullchain-file /usr/src/trojan-cert/fullchain.cer
	if test -s /usr/src/trojan-cert/fullchain.cer; then
	systemctl start nginx
        cd /usr/src
	#wget https://github.com/trojan-gfw/trojan/releases/download/v1.13.0/trojan-1.13.0-linux-amd64.tar.xz
	wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
	latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
	rm -f latest
	wget https://github.com/trojan-gfw/trojan/releases/download/v${latest_version}/trojan-${latest_version}-linux-amd64.tar.xz >/dev/null 2>&1
	tar xf trojan-${latest_version}-linux-amd64.tar.xz >/dev/null 2>&1
	#下载trojan客户端
	wget https://github.com/atrandys/trojan/raw/master/trojan-cli.zip >/dev/null 2>&1
	wget -P /usr/src/trojan-temp https://github.com/trojan-gfw/trojan/releases/download/v${latest_version}/trojan-${latest_version}-win.zip >/dev/null 2>&1
	unzip trojan-cli.zip >/dev/null 2>&1
	unzip /usr/src/trojan-temp/trojan-${latest_version}-win.zip -d /usr/src/trojan-temp/ >/dev/null 2>&1
	cp /usr/src/trojan-cert/fullchain.cer /usr/src/trojan-cli/fullchain.cer
	mv -f /usr/src/trojan-temp/trojan/trojan.exe /usr/src/trojan-cli/ 
	trojan_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
	cat > /usr/src/trojan-cli/config.json <<-EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "$your_domain",
    "remote_port": 444,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "fullchain.cer",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	"sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF
	rm -rf /usr/src/trojan/server.conf
	cat > /usr/src/trojan/server.conf <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 444,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/usr/src/trojan-cert/fullchain.cer",
        "key": "/usr/src/trojan-cert/private.key",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
	"prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
	cd /usr/src/trojan-cli/
	zip -q -r trojan-cli.zip /usr/src/trojan-cli/
	trojan_path=$(cat /dev/urandom | head -1 | md5sum | head -c 16)
	mkdir /usr/share/nginx/html/${trojan_path}
	mv /usr/src/trojan-cli/trojan-cli.zip /usr/share/nginx/html/${trojan_path}/
	#增加启动脚本
	
cat > ${systempwd}trojan.service <<-EOF
[Unit]  
Description=trojan  
After=network.target  
   
[Service]  
Type=simple  
PIDFile=/usr/src/trojan/trojan/trojan.pid
ExecStart=/usr/src/trojan/trojan -c "/usr/src/trojan/server.conf"  
ExecReload=  
ExecStop=kill -9 $(pidof /usr/src/trojan/trojan)  
PrivateTmp=true  
   
[Install]  
WantedBy=multi-user.target
EOF

	chmod +x ${systempwd}trojan.service
	systemctl start trojan.service
	systemctl enable trojan.service
	green "======================================================================"
	green "Trojan已安装完成，请使用以下链接下载trojan客户端，此客户端已配置好所有参数"
	green "1、复制下面的链接，在浏览器打开，下载客户端，注意此下载链接将在1个小时后失效"
	blue "http://${your_domain}/$trojan_path/trojan-cli.zip"
	green "2、将下载的压缩包解压，打开文件夹，打开start.bat即打开并运行Trojan客户端"
	green "3、打开stop.bat即关闭Trojan客户端"
	green "4、Trojan客户端需要搭配浏览器插件使用，例如switchyomega等"
	green "======================================================================"
	else
        red "==================================="
	red "https证书没有申请成果，自动安装失败"
	green "不要担心，你可以手动修复证书申请"
	green "1. 重启VPS"
	green "2. 重新执行脚本，使用修复证书功能"
	red "==================================="
	fi
}
function install_trojan(){
nginx_status=`ps -aux | grep "nginx: worker" |grep -v "grep"`
if [ -n "$nginx_status" ]; then
    systemctl stop nginx
fi
$systemPackage -y install net-tools socat
Port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
Port444=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 444`
if [ -n "$Port80" ]; then
    process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
    red "==========================================================="
    red "检测到80端口被占用，占用进程为：${process80}，本次安装结束"
    red "==========================================================="
    exit 1
fi
if [ -n "$Port444" ]; then
    process444=`netstat -tlpn | awk -F '[: ]+' '$5=="444"{print $9}'`
    red "============================================================="
    red "检测到444端口被占用，占用进程为：${process444}，本次安装结束"
    red "============================================================="
    exit 1
fi
CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
if [ "$CHECK" != "SELINUX=disabled" ]; then
    green "检测到SELinux开启状态，添加放行80/444端口规则"
    yum install -y policycoreutils-python >/dev/null 2>&1
    semanage port -a -t http_port_t -p tcp 80
    semanage port -a -t http_port_t -p tcp 444
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
    firewall_status=`firewall-cmd --state`
    if [ "$firewall_status" == "running" ]; then
        green "检测到firewalld开启状态，添加放行80/444端口规则"
        firewall-cmd --zone=public --add-port=80/tcp --permanent
	firewall-cmd --zone=public --add-port=444/tcp --permanent
	firewall-cmd --reload
    fi
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
    ufw_status=`systemctl status ufw | grep "Active: active"`
    if [ -n "$ufw_status" ]; then
        ufw allow 80/tcp
        ufw allow 444/tcp
    fi
    apt-get update
elif [ "$release" == "debian" ]; then
    apt-get update
fi
$systemPackage -y install  nginx wget unzip zip curl tar >/dev/null 2>&1
systemctl enable nginx
systemctl stop nginx
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
        install
	
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
	    install
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
	green "请将/usr/src/trojan-cert/下的fullchain.cer下载放到客户端trojan-cli文件夹"
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

function remove_trojan(){
    red "================================"
    red "即将卸载trojan"
    red "同时卸载安装的nginx"
    red "================================"
    systemctl stop trojan
    systemctl disable trojan
    rm -f ${systempwd}trojan.service
    if [ "$release" == "centos" ]; then
        yum remove -y nginx
    else
        apt autoremove -y nginx
    fi
    rm -rf /usr/src/trojan*
    rm -rf /usr/share/nginx/html/*
    green "=============="
    green "trojan删除完毕"
    green "=============="
}

function update_trojan(){
    /usr/src/trojan/trojan -v 2>trojan.tmp
    curr_version=`cat trojan.tmp | grep "trojan" | awk '{print $4}'`
    wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
    latest_version=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
    rm -f latest
    rm -f trojan.tmp
    if version_lt "$curr_version" "$latest_version"; then
        green "当前版本$curr_version,最新版本$latest_version,开始升级……"
        mkdir trojan_update_temp && cd trojan_update_temp
        wget https://github.com/trojan-gfw/trojan/releases/download/v${latest_version}/trojan-${latest_version}-linux-amd64.tar.xz >/dev/null 2>&1
        tar xf trojan-${latest_version}-linux-amd64.tar.xz >/dev/null 2>&1
        mv ./trojan/trojan /usr/src/trojan/
        cd .. && rm -rf trojan_update_temp
        systemctl restart trojan
	/usr/src/trojan/trojan -v 2>trojan.tmp
	green "trojan升级完成，当前版本：`cat trojan.tmp | grep "trojan" | awk '{print $4}'`"
	rm -f trojan.tmp
    else
        green "当前版本$curr_version,最新版本$latest_version,无需升级"
    fi
   
   
}

function showme_sub(){
    port=`cat /usr/src/trojan/server.conf | grep local_port | awk -F '[,]+|[ ]' '{ print $(NF-1) }'`
    domain=`grep 'server_name' /etc/nginx/nginx.conf | awk '{for(i=1;i<=NF;i++) if($i=="server_name") print $(i+1)}' | sed 's/;//'`
    password=`cat /usr/src/trojan/server.conf | grep password | head -n 1 | awk -F '["]' '{ print $(NF-1) }'`
    green " ======================================="
    red "注意：下面仅仅是普通节点订阅链接，如使用clash等软件，请自行转换"
    green "你的Trojan订阅链接是：trojan://${password}@${domain}:${port}"
    green " ======================================="
}

function clear_logs() {
  echo > /var/log/wtmp
  echo > /var/log/btmp
  echo > /var/log/lastlog
  echo > /var/log/secure
  echo > /var/log/messages
  echo > /var/log/syslog
  echo > /var/log/xferlog
  echo > /var/log/auth.log
  echo > /var/log/user.log
  cat /dev/null > /var/adm/sylog
  cat /dev/null > /var/log/maillog
  cat /dev/null > /var/log/openwebmail.log
  cat /dev/null > /var/log/mail.info
  echo > /var/run/utmp
  echo > /root/.bash_history
  history -cw

  # 在函数内部输出提示文字
  echo "日志已清除完毕！"
}

function my_cert(){
#!/bin/bash

# 确保脚本以 root 身份运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 身份运行此脚本。"
    exit 1
fi

# 检查系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "无法确定操作系统类型，请手动检查。"
    exit 1
fi

# 检查并安装 socat
if ! command -v socat &> /dev/null; then
    echo "socat 未安装，正在安装 socat..."
    if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
        apt update
        apt install -y socat
    elif [ "$OS" == "centos" ]; then
        yum install -y socat
    else
        echo "不支持的操作系统。"
        exit 1
    fi
    if [ $? -ne 0 ]; then
        echo "socat 安装失败，请检查错误信息。"
        exit 1
    fi
else
    echo "socat 已安装。"
fi

# 检查 nginx 服务状态
nginx_status=$(systemctl is-active nginx)
if [ "$nginx_status" == "active" ]; then
    echo "nginx 服务正在运行，准备停止..."
    systemctl stop nginx
    if [ $? -ne 0 ]; then
        echo "停止 nginx 失败，请检查错误信息。"
        exit 1
    fi
else
    echo "nginx 服务未运行，无需停止。"
fi

# 检查端口 80 是否被占用
if lsof -i:80 &> /dev/null; then
    echo "端口 80 被占用，无法继续。"
    exit 1
fi

# 安装 acme.sh
if [ ! -d "$HOME/.acme.sh" ]; then
    echo "正在安装 acme.sh..."
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        echo "acme.sh 安装失败，请检查错误信息。"
        exit 1
    fi
else
    echo "acme.sh 已安装。"
fi

# 设置默认 CA 为 Let’s Encrypt
echo "设置默认 CA 为 Let’s Encrypt..."
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

# 获取用户输入的域名
read -p "请输入主域名: " main_domain
domains=($main_domain)
while true; do
    read -p "请输入附加域名（或按 Enter 键结束输入）: " additional_domain
    if [ -z "$additional_domain" ]; then
        break
    fi
    domains+=("$additional_domain")
done

# 生成域名参数
domain_args=""
for domain in "${domains[@]}"; do
    domain_args="$domain_args -d $domain"
done

# 申请测试证书
echo "申请测试证书..."
~/.acme.sh/acme.sh --issue $domain_args --standalone -k ec-256 --force --test
if [ $? -ne 0 ]; then
    echo "测试证书申请失败，请检查错误信息。"
    exit 1
fi

# 删除测试证书
echo "删除测试证书..."
rm -rf "$HOME/.acme.sh/${main_domain}_ecc"

# 申请正式证书
echo "申请正式证书..."
~/.acme.sh/acme.sh --issue $domain_args --standalone -k ec-256 --force
if [ $? -ne 0 ]; then
    echo "正式证书申请失败，请检查错误信息。"
    exit 1
fi

# 创建证书存储目录
echo "创建证书存储目录..."
mkdir -p /usr/src/trojan-cert/

# 安装证书
echo "安装证书..."
~/.acme.sh/acme.sh --installcert -d "$main_domain" --fullchainpath /usr/src/trojan-cert/fullchain.cer --keypath /usr/src/trojan-cert/privkey.key --ecc --force
if [ $? -ne 0 ]; then
    echo "证书安装失败，请检查错误信息。"
    exit 1
fi

# 启动 nginx 服务（如果之前正在运行）
if [ "$nginx_status" == "active" ]; then
    echo "重新启动 nginx 服务..."
    systemctl start nginx
    if [ $? -ne 0 ]; then
        echo "启动 nginx 失败，请检查错误信息。"
        exit 1
    fi
fi

# 设置自动续签任务
echo "设置自动续签任务..."
# 移除之前的重复任务
crontab -l | grep -v "acme.sh --cron" | crontab -
# 添加新的 cron 任务
(crontab -l 2>/dev/null; echo "0 0 * * * ~/.acme.sh/acme.sh --cron --home ~/.acme.sh > /dev/null 2>&1") | crontab -
if [ $? -ne 0 ]; then
    echo "自动续签任务设置失败，请检查错误信息。"
    exit 1
fi

echo "证书申请、安装和自动续签任务设置完成。"

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
    apt install net-tools -y
    yum install net-tools -y
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
        yum install epel-release -y
        yum clean all
        yum makecache
        yum update -y
        yum install git gcc glibc-headers gettext autoconf libtool automake make pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel mbedtls-devel -y


    elif [ "$release" == "ubuntu" ]; then
        ufw_status=`systemctl status ufw | grep "Active: active"`
        if [ -n "$ufw_status" ]; then
            ufw allow $ss_port/tcp
            ufw reload
        fi
        apt update -y
        apt install -y --no-install-recommends git libssl-dev gettext build-essential autoconf libtool libpcre3 libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev pkg-config
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

start_menu(){
    clear
    green " ======================================="
    green " 介绍：一键安装trojan      "
    green " 系统：centos7+/debian9+/ubuntu16.04+"
    blue " 声明："
    red " *请不要在任何生产环境使用此脚本"
    red " *请不要有其他程序占用80和444端口"
    red " *若是第二次使用脚本，请先执行卸载trojan"
    green " ======================================="
    echo
    green " 1. 安装trojan"
    red " 2. 卸载trojan"
    green " 3. 升级trojan"
    green " 4. 修复证书"
    green " 5. show订阅"
    green " 6. 清理日志"
    green " 7. 安装ShadowSocks"
    green " 8. 卸载ShadowSocks"
    green " 9.my_cert申请"
    blue " 0. 退出脚本"
    echo
    read -p "请输入数字 :" num
    case "$num" in
    1)
    install_trojan
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
    showme_sub 
    ;;
    6)
    clear_logs 
    ;;
    7)
    install_ss 
    ;;
    8)
    remove_ss 
    ;;
    9)
    my_cert 
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    red "请输入正确数字"
    sleep 1s
    start_menu
    ;;
    esac
}

start_menu
