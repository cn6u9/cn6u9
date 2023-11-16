
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
