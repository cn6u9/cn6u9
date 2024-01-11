# myvps
```
yum -y install epel-release
yum install centos-release-scl -y
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

### 定时重启定时改端口
```
0 2 * * * /sbin/reboot
30 2 * * * /opt/port.sh

```

### 自动改端口
```
#!/bin/bash

# JSON configuration file path
config_file="/usr/src/trojan/server.conf"

# Trojan URI file path
trojan_uri_file="/usr/share/nginx/html/trojan_url_aabbcc123.txt"

# Generate a random port number between 50000 and 51000
random_port=$(shuf -i 50000-51000 -n 1)

# Update the "local_port" value in the JSON file
sed -i "s/\"local_port\": [0-9]\+/\"local_port\": $random_port/" "$config_file"

echo "Updated local_port to $random_port"

# Generate Trojan URI
trojan_uri="trojan://password@hk.org:$random_port#HK1"

# Base64 encode the Trojan URI
encoded_trojan_uri=$(echo -n "$trojan_uri" | base64)

# Write encoded Trojan URI to file
echo "$encoded_trojan_uri" > "$trojan_uri_file"

echo "Encoded Trojan URI written to $trojan_uri_file"

systemctl restart trojan
systemctl restart nginx

```
