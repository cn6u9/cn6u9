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

echo "Hello from start.sh!"
nohup sh /root/PP/start.sh &
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
