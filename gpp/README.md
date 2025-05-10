# 运行客户端

[从releases下载](https://github.com/danbai225/gpp/releases)下载对应系统的客户端以管理员身份运行

点击页面上的`Game`或`Http`字样弹出节点列表窗口，在下方粘贴服务端的链接完成节点导入。
在节点列表选择你的加速节点，如何开始加速。
客户端因为软件无法出墙下载需要手动下载  
wget https://github.com/malikshi/sing-box-geo/releases/latest/download/geosite.db  
wget https://github.com/malikshi/sing-box-geo/releases/latest/download/geoip.db  
通常的路径是C:\Users\admin\.gpp
## mac修复损坏
安装后命令行执行
```bash
sudo xattr -r -d com.apple.quarantine /Applications/gpp.app
```

# 编译

## 编译服务端

使用`golang`编译 `cmd/gpp/main.go`获得服务端可执行文件。
```
go build cmd/gpp/main.go
mv main gpp
cp gpp /usr/local/gpp/
```

## 编译GUI客户端

gui的客户端需要自建构建，需要安装`wails`、`npm`和`golang`，安装方法如下

- 安装`golang`，[下载地址](https://golang.org/dl/)
- 安装`npm` [下载地址](https://nodejs.org/en/download/)
- 安装`wails`，`go install github.com/wailsapp/wails/v2/cmd/wails@latest`

使用`wails`编译

```
export NODE_OPTIONS="--max-old-space-size=4096"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 wails build -tags with_gvisor --skipbindings
```

# config解释

## 服务端

配置存放为服务端二进制文件当前目录的`config.json`

- protocol 协议
- port 端口
- addr 绑定地址
- uuid 认证用途

```json
{
  "protocol": "vless",
  "port": 5123,
  "addr": "0.0.0.0",
  "uuid":"xxx-xx-xx-xx-xxx"
}
```

## 客户端

配置存放为客户端二进制文件当前目录的`config.json`或者用户目录下`<userhome>/.gpp/config.json`

- peer_list 节点列表
- proxy_dns 代理dns
- local_dns 直连dns
- sub_addr 订阅地址
- rules [代理规则](https://sing-box.sagernet.org/zh/configuration/route/rule)

```json
{
  "peer_list": [
    {
      "name": "直连",
      "protocol": "direct",
      "port": 0,
      "addr": "direct",
      "uuid": ""
    },
    {
      "name": "hk",
      "protocol": "vless",
      "port": 5123,
      "addr": "xxx.xx.xx.xx",
      "uuid": "xxx-xxx-xx-xxx-xxx"
    }
  ],
  "proxy_dns": "8.8.8.8",
  "local_dns": "223.5.5.5",
  "sub_addr": "https://sub.com",
  "rules": [
    {
      "process_name": "C://1.exe",
      "outbound": "direct"
    },
    {
      "domain": "ipv4.ip.sb",
      "outbound": "proxy"
    }
  ]
}
```


