
# 
```
yum -y install epel-release
yum install centos-release-scl -y
yum update && yum upgrade
```

### Usage
```
bash <(curl -fsSL https://raw.githubusercontent.com/cn6u9/cn6u9/main/hysteria2/hysteria.sh)

```

### Enable BBR
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
 chmod +x tcp.sh
 ./tcp.sh
```


### Usage tuic 需要glibc 2.21以上
```
wget -N --no-check-certificate https://raw.githubusercontent.com/cn6u9/cn6u9/main/hysteria2/tuic.sh && bash tuic.sh
```
```
{
    "relay": {
        "server": "g.com:443",
        "uuid": "22f5c0b9-5b82-4b80-acd7-7e2e4ad1d31c3",
        "password": "sSuXl1fPo03",
        "ip": "10.0.0.1",
        "congestion_control": "bbr",
        "alpn": ["h3"]
    },
    "local": {
        "server": "127.0.0.1:50000"
    },
    "log_level": "info"
}
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
