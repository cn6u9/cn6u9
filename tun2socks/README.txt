
### 方案一
```
start.bat
tun2socks-windows-4.0-amd64.exe -tunName tap -tunAddr 10.0.0.2 -tunGw 10.0.0.1 -proxyType socks -proxyServer 127.0.0.1:1080 -dnsServer 8.8.8.8,8.8.4.4

//安装完成tap-windows-9.22之后需要打开网卡改变名字为tap，需要首先运行上面命令，否则下面route找不到10.0.0.1,而且下面的命令需要高权限运行，上面的tun2socks不需要高权限运行

route delete 0.0.0.0 mask 0.0.0.0

route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 6

route add 4.151.135.217 192.168.7.1 metric 5

// 4.151.135.217 是你的1080代理的vps地址，192.168.7.1是你的默认网卡网关。


stop.bat
恢复网关
route delete 0.0.0.0 mask 0.0.0.0

route add 0.0.0.0 mask 0.0.0.0 192.168.7.1 metric 50


build

git clone https://github.com/eycorsican/go-tun2socks.git
cd /go-tun2socks/cmd/tun2socks/
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -ldflags="-s -w"


```
### 方案二
```

git clone https://github.com/xjasonlyu/tun2socks.git
cd tun2socks
make

需要把默认上网的网卡改名成wifi
改变网卡名字，Ethernet0是系统默认，wifi是下面命令需要的，需要把另一个压缩包里的wintun.dll解压过来

windows10下可用
netsh interface set interface name="Ethernet0" newname="wifi"
start tun2socks-windows-amd64.exe -device wintun -proxy socks5://127.0.0.1:1080 -interface "wifi"
netsh interface ipv4 set address name="wintun" source=static addr=192.168.123.1 mask=255.255.255.0
netsh interface ipv4 set dnsservers name="wintun" static address=8.8.8.8 register=none validate=no
netsh interface ipv4 add route 0.0.0.0/0 "wintun" 192.168.123.1 metric=1
route add 4.151.135.217 192.168.7.1 metric 5

windows 2008 下目前不可用，需要改写
netsh interface set interface name="Ethernet0" newname="wifi"
start tun2socks-windows-amd64.exe -device wintun -proxy socks5://127.0.0.1:3333 -interface "wifi"
netsh interface ipv4 set address name="wintun" source=static addr=192.168.123.100 mask=255.255.255.0 gateway=192.168.123.1
netsh interface ipv4 set dnsservers name="wintun" static address=8.8.8.8 register=none validate=no
netsh interface ipv4 add route prefix=0.0.0.0/0 interface="wintun" nexthop=192.168.123.1 metric=1
route add 46.2.1.9 mask 255.255.255.255 192.168.8.1 metric 5


```
```

添加多个路由表，那个走得通就走那个
@echo off
route delete 0.0.0.0
route add 1.1.1.1 mask 255.255.255.255 192.168.0.1
ping -n 2 1.1.1.1
route add 2.2.2.2 mask 255.255.255.255 192.168.0.1
ping -n 2 2.2.2.2
route add 3.3.3.3 mask 255.255.255.255 192.168.0.1
ping -n 2 3.3.3.3
pause
```
