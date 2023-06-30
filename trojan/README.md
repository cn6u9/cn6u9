# myvps
```
yum -y install epel-release
yum update && yum upgrade
```

### Usage
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/cn6u9/cn6u9/main/trojan/myvps.sh"
 chmod +x myvps.sh
 ./myvps.sh

```
### Client
```
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1086,
    "remote_addr": "1.baidu.org",
    "remote_port": 444,
    "password": [
        "pass"
    ],
    "ssl": {
        "sni": "1.baidu.org"
    },
    "mux" :{
        "enabled": false
    },
    "router":{
        "enabled": true,
        "bypass": [
            "geoip:cn",
            "geoip:private",
            "geosite:cn",
            "geosite:geolocation-cn"
        ],
        "block": [
            "geosite:category-ads"
        ],
        "proxy": [
            "geosite:geolocation-!cn"
        ]
    }
}
```
### Enable BBR
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
 chmod +x tcp.sh
 ./tcp.sh
```


