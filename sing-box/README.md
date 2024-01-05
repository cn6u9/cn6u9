## download




```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/cn6u9/cn6u9/main/sing-box/install.sh" && chmod 700 /root/install.sh && /root/install.sh
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
 echo > /var/log/wtmp //清除用户登录记录
 echo > /var/log/btmp //清除尝试登录记录
 echo > /var/log/lastlog //清除最近登录信息
 echo > /var/log/secure //登录信息
 echo > /var/log/messages
 echo > /var/log/syslog //记录系统日志的服务
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
```


## 开机启动bash，服务自动创建
```
#!/bin/bash

service_name="my_service"


service_description="My Service"


service_executable="/opt/start.sh"


cat <<'EOF' | sudo tee $service_executable > /dev/null
#!/bin/bash


# /path/to/your/actual/service_executable

#!/bin/bash

# Continuously check if the pptt process is running
while true; do
  # Check if the process is running
  if ! pgrep pptter >/dev/null 2>&1; then
    # If the process is not running, start it
cd /root// &&  /root//pter -p 88 &
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



# 
```
yum -y install epel-release
yum install centos-release-scl -y
yum update && yum upgrade
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





