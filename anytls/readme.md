### install
```
bash <(curl -Lso- https://raw.githubusercontent.com/cn6u9/cn6u9/refs/heads/main/anytls/anytls.sh)
```
### client
```
wget https://github.com/anytls/anytls-go/releases/download/v0.0.11/anytls_0.0.11_linux_amd64.zip
unzip anytls_0.0.11_linux_amd64.zip
cp anytls-client /usr/bin
anytls-client -l 127.0.0.1:7893 -s 服务器ip:端口 -p 密码
```
