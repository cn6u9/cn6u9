## download


```
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/cn6u9/cn6u9/main/sing-box/install.sh" && chmod 700 /root/install.sh && /root/install.sh
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


