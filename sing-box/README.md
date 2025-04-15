## download




```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/cn6u9/cn6u9/main/sing-box/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/cn6u9/cn6u9/main/sing-box/wireguard-install.sh" && chmod 700 /root/wireguard-install.sh && /root/wireguard-install.sh
```

### wireguard 服务端自动改端口写文件
```
#!/bin/bash
change_port() {
    cp /root/a.conf /etc/wireguard/client.conf
    cp /root/b.conf /etc/wireguard/client.conf
    cp /root/c.conf /etc/wireguard/client.conf
    cp /root/0.conf /etc/wireguard/client.conf
    cp /root/1.conf /etc/wireguard/client.conf

    rand(){
        min=$1
        max=$(($2-$min+1))
        num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
        echo $(($num%$max+$min))  
    }

    wireguard_changeport(){
        clear

        cd /etc/wireguard

        port=$(rand 10000 60000)

        echo "**********************************"
        echo          new port is: $port
        echo "**********************************"

        # Write the new port to the file
        echo $port > /var/www/html/wireguardport.txt
        echo $port > /usr/share/nginx/html/wireguardport.txt

        sudo sed -ri "s|^.*ListenPort = .*$|ListenPort = $port|" wg0.conf
        sudo sed -ri "s|(^.*Endpoint.*\>:).*|\1$port|" client.conf
        sudo sed -ri "s|(^.*Endpoint.*\>:).*|\1$port|" client0.conf
    }

    sudo wg-quick down wg0
    wireguard_changeport
    sudo wg-quick up wg0
    sudo wg
    sudo qrencode -t ansiutf8 < /etc/wireguard/client.conf
    sudo qrencode -t ansiutf8 < /etc/wireguard/client0.conf
}

change_port


```
### wireguard 客户端自动改端口
```

#!/bin/bash
#find /|grep openvpn查找本地配置文件所在位置kali下面是/etc/NetworkManager/system-connections/a.nmconnection
# Define the local configuration file path
config_file="/etc/NetworkManager/system-connections/a.nmconnection"

# Fetch the current port from WireGuard configuration
current_port=$(grep -oP '(?<=endpoint=.*:)\d+' "$config_file")

# Fetch the remote port number using curl
remote_port=$(curl -s http://123.2.4.0/wireguardport.txt)

# Check if the current port matches the remote port
if [ "$current_port" == "$remote_port" ]; then
    echo "Ports match. No changes required."
    exit 0
else
    echo "Ports do not match. Updating port number..."

    # Replace the port number in the WireGuard configuration file
    sudo sed -ri "s|(^.*endpoint=.*:).*|\1$remote_port|" "$config_file"

    # Restart NetworkManager to apply the updated configuration
    sudo systemctl restart NetworkManager

    echo "Port number updated to $remote_port."
fi


```
### ubuntu install nginx
```
apt-get install nginx
systemctl status nginx
sudo systemctl enable nginx

```


### 客户端
```
git clone https://github.com/GUI-for-Cores/GUI.for.SingBox.git
git clone https://github.com/Night-stars-1/clash-meta.git
or
go env -w GOPROXY=https://goproxy.io,direct

git clone https://github.com/JMVoid/mihomo.git
cd mihomo && go mod download
go build

编译tun模式:
go build -tags with_gvisor

CGO_ENABLED=0  GOOS=windows  GOARCH=amd64 go build -tags with_gvisor

ui界面
wget https://github.com/MetaCubeX/metacubexd/releases/download/v1.141.0/compressed-dist.tgz
解压到系统80端口或者python3 -m http.server 80

机场使用
git clone https://github.com/hsernos/Txray.git
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build Txray.go
sub add http:111.111.111.11/ -r test
sub update-node

node -d
node tcping

setting
setting socks 1080
# 设置启动时从订阅更新节点
setting run_before "sub update-node"
# 设置启动时对节点进行tcp测试，然后运行延迟最小的那个
setting run_before "node tcping | run"

run 1-6





```

# 
```
yum -y install epel-release
yum install centos-release-scl -y
yum update && yum upgrade
```


### Enable BBR
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
 chmod +x tcp.sh
 ./tcp.sh
```


```
firewall-cmd --zone=public --add-port=65333/tcp --permanent
firewall-cmd --zone=public --add-port=65111/udp --permanent

firewall-cmd --reload
systemctl start firewalld
systemctl enable firewalld

systemctl stop firewalld
systemctl disable firewall
```
```
0 2 * * * /sbin/reboot
30 2 * * * /opt/port.sh
```
## 设置22端口
```
#!/bin/bash

# 设置新的SSH端口
new_ssh_port=22222

# 检查系统类型
if [ -f /etc/redhat-release ]; then
    os_type="centos"
elif [ -f /etc/debian_version ]; then
    os_type="debian"
elif [ -f /etc/lsb-release ]; then
    os_type="ubuntu"
elif [ -f /etc/freebsd-update.conf ]; then
    os_type="freebsd"
else
    echo "未知的操作系统类型，脚本可能无法正常工作。"
    exit 1
fi

echo "检测到的操作系统类型: $os_type"

# 修改SSH端口
echo "修改SSH端口为$new_ssh_port"
sed -i "s/^#Port 22/Port $new_ssh_port/" /etc/ssh/sshd_config

# 重启SSH服务
echo "重启SSH服务"
if [ "$os_type" == "centos" ]; then
    systemctl restart sshd
else
    service ssh restart
fi

# 检查并修改防火墙规则
echo "检查并修改防火墙规则"
if command -v firewall-cmd &> /dev/null; then
    # CentOS 7+ 使用 firewalld
    echo "使用 firewalld"
    firewall-cmd --zone=public --add-port=$new_ssh_port/tcp --permanent
    firewall-cmd --reload
elif command -v ufw &> /dev/null; then
    # Ubuntu 使用 ufw
    echo "使用 ufw"
    ufw allow $new_ssh_port
    ufw reload
elif command -v iptables &> /dev/null; then
    # 其他系统使用 iptables
    echo "使用 iptables"
    iptables -A INPUT -p tcp --dport $new_ssh_port -j ACCEPT
    service iptables save
    service iptables restart
else
    echo "无法检测到防火墙管理工具，未做防火墙规则修改。"
fi

echo "完成！请确保防火墙规则已经修改，并使用新端口连接SSH。"

```


## 创建服务,启动一个/opt/start.sh
```
#!/bin/bash

service_name="my_service"


service_description="My Service"


service_executable="/opt/start.sh"


cat <<'EOF' | sudo tee $service_executable > /dev/null
#!/bin/bash


# /path/to/your/actual/service_executable

#!/bin/bash
chmod +x /etc/rc.d/rc.local
chmod +x /etc/rc.local
# Continuously check if the pptt process is running
while true; do
  # Check if the process is running
  if ! pgrep pptter >/dev/null 2>&1; then
    # If the process is not running, start it
cd /opt/ && /opt/pptter -p 8080 -tlsp 443 -tlsc /etc/cert/fullchain.pem -tlsk /etc/cert/privkey.pem &
#cd /opt/ && /opt/pptter -p 8080 -tlsp 443 -tlsc /etc/v2ray-agent/tls/kuai.369.org.crt -tlsk /etc/v2ray-agent/tls/kuai.369.org.key &
  fi

  # Sleep for 1 second before checking again
  sleep 10
done

# Exit the script
exit 0

EOF


sudo chmod +x $service_executable


cat <<EOF | sudo tee /etc/systemd/system/$service_name.service > /dev/null
[Unit]
Description=$service_description
After=network.target

[Service]
Type=simple
ExecStart=$service_executable
Restart=always

[Install]
WantedBy=default.target
EOF

sudo chmod 644 /etc/systemd/system/$service_name.service

sudo systemctl daemon-reload

sudo systemctl start $service_name
sudo systemctl enable $service_name

sudo systemctl status $service_name

```
### 12小时重启一次，每9个小时重启一次。
```
0 0 * * * systemctl restart my_service.service
0 */9 * * * systemctl restart wg-quick@wg0.service


```
### 设置中国时区
```
#!/bin/bash

# 安装NTP
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y ntp
elif command -v yum &> /dev/null; then
    sudo yum install -y ntp
else
    echo "无法识别的包管理器。请手动安装NTP。"
    exit 1
fi

# 设置时区为中国标准时间
sudo timedatectl set-timezone Asia/Shanghai

# 配置NTP服务器
NTP_CONF_FILE="/etc/ntp.conf"
NTP_SERVERS="server 0.cn.pool.ntp.org iburst
server 1.cn.pool.ntp.org iburst
server 2.cn.pool.ntp.org iburst
server 3.cn.pool.ntp.org iburst"

sudo bash -c "echo '$NTP_SERVERS' > $NTP_CONF_FILE"

# 重启NTP服务
if command -v systemctl &> /dev/null; then
    sudo systemctl restart ntp || sudo systemctl restart ntpd
else
    echo "无法识别的系统管理工具。请手动重启NTP服务。"
    exit 1
fi

# 检查时间同步状态
timedatectl status
ntpq -p

```

### tuic自动改端口
```
#!/bin/bash

# JSON configuration file path
config_file="/etc/v2ray-agent/sing-box/conf/config.json"

# Trojan URI file path
trojan_uri_file="/etc/v2ray-agent/subscribe/default/tuic_url_aabbcc123.txt"

# Generate a random port number between 50000 and 51000
random_port=$(shuf -i 50000-52000 -n 1)

awk -v random_port="$random_port" '/"listen_port":/ {gsub(/[0-9]+/, random_port, $2)}1' "$config_file" > temp_config && mv temp_config /etc/v2ray-agent/sing-box/conf/config.json

echo "Updated server port to $random_port"


# Generate Trojan URI
trojan_uri="tuic://db4f4ed-f1096612a10f:000bRt3r1@10.10.8.17:$random_port?congestion_control=bbr&alpn=h3&sni=google.org&udp_relay_mode=quic&allow_insecure=0#tuichk"


# Base64 encode the Trojan URI
encoded_trojan_uri=$(echo -n "$trojan_uri" | base64)

# Write encoded Trojan URI to file
echo "$encoded_trojan_uri" > "$trojan_uri_file"

echo "Encoded Trojan URI written to $trojan_uri_file"

systemctl restart nginx.service
systemctl restart sing-box.service


```

### hy2自动改端口
```
#!/bin/bash

# JSON configuration file path
config_file="/etc/v2ray-agent/sing-box/conf/config.json"

# Trojan URI file path
trojan_uri_file="/etc/v2ray-agent/subscribe/default/tuic_url_aabbcc123.txt"

# Generate a random port number between 50000 and 51000
random_port=$(shuf -i 50000-52000 -n 1)

awk -v random_port="$random_port" '/"listen_port":/ {gsub(/[0-9]+/, random_port, $2)}1' "$config_file" > temp_config && mv temp_config /etc/v2ray-agent/sing-box/conf/config.json

echo "Updated server port to $random_port"


# Generate Trojan URI
trojan_uri="hysteria2://a92f7ee5-aae7-4d@baidu.org:$random_port?peer=baidu.org&insecure=0&sni=baidu.org&alpn=h3#a92f7ee5-singbox_hysteria2"

# Base64 encode the Trojan URI
encoded_trojan_uri=$(echo -n "$trojan_uri" | base64)

# Write encoded Trojan URI to file
echo "$encoded_trojan_uri" > "$trojan_uri_file"

echo "Encoded Trojan URI written to $trojan_uri_file"

systemctl restart nginx.service
systemctl restart sing-box.service



```

### openwrt设置开机启动
```
#!/bin/bash

# 创建启动脚本文件
cat <<EOF > /etc/init.d/mystart.sh
#!/bin/sh /etc/rc.common

START=99

start() {
    # 在此处添加启动程序的命令
    sh /home/rrest.sh
}

stop() {
    # 在此处添加停止程序的命令
    killall rrest.sh
}
EOF

# 添加执行权限
chmod +x /etc/init.d/mystart.sh

# 启用启动脚本
/etc/init.d/mystart.sh enable

# 启动服务
/etc/init.d/mystart.sh start
touch /home/rrest.sh
chmod +x /home/rrest.sh
```

### bash设置凌晨3点重启

```
#!/bin/bash

while true; do
    # 获取当前时间
    current_time=$(date +%H:%M)

    # 判断是否是凌晨3:00
    if [ "$current_time" == "03:00" ]; then
        # 如果是，执行reboot命令
        reboot
    else
        echo "It's not 3:00 AM, skipping reboot."
    fi

    # 每隔一段时间再次检查
    sleep 60 # 每隔60秒检查一次
done &

```

### Usage tuic 需要glibc 2.21以上下面自动下载编译glibc
```
#aHR0cHM6Ly93cmxvZy5jbi8yMDIyLzEwLzEyODEv
yum install centos-release-scl -y
yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++ devtoolset-8-binutils 
echo "source /opt/rh/devtoolset-8/enable" >> /etc/profile 
source /etc/profile


wget https://ftp.gnu.org/gnu/make/make-4.3.tar.gz 
tar -xzvf make-4.3.tar.gz 
cd make-4.3/ 
./configure --prefix=/usr/local/make 
make 
make install 

cd /usr/bin/ 
mv make make.bak # backup 
ln -sv /usr/local/make/bin/make /usr/bin/make

wget https://ftp.gnu.org/gnu/glibc/glibc-2.28.tar.gz 
tar -xzvf glibc-2.28.tar.gz 
cd glibc-2.28
mkdir build && cd build 
cd /root/glibc-2.28/build 
yum install bison -y
../configure --prefix=/usr --disable-profile --enable-add-ons --with-headers=/usr/include --with-binutils=/usr/bin 
make 
make install

```





