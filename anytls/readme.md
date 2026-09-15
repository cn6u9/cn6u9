### install
```
bash <(curl -Lso- https://raw.githubusercontent.com/cn6u9/cn6u9/refs/heads/main/anytls/anytls.sh)
```
```
wget https://raw.githubusercontent.com/cn6u9/cn6u9/refs/heads/main/anytls/anytls.sh
chmod +x anytls.sh
bash anytls.sh
```
### client
```
# 用法:
#   bash anytls-client.sh run      # 执行一次
#   bash anytls-client daemon   # 守护运行，每3小时一次
#   bash anytls-client stop     # 停止所有客户端
#   bash anytls-client status   # 查看当前状态
wget https://raw.githubusercontent.com/cn6u9/cn6u9/refs/heads/main/anytls/anytls_client.sh
chmod +x anytls_client.sh
bash anytls_client.sh --help

```
