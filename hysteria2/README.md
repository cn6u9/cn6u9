
# 
```
yum -y install epel-release
yum update && yum upgrade
```

### Usage
```
bash <(curl -fsSL https://raw.githubusercontent.com/cn6u9/cn6u9/main/hysteria2/hysteria.sh)

```
### Usage tuic 需要glibc 2.21以上
```
wget -N --no-check-certificate https://raw.githubusercontent.com/cn6u9/cn6u9/main/hysteria2/tuic.sh && bash tuic.sh
```
### Enable BBR
```
 wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
 chmod +x tcp.sh
 ./tcp.sh
```

```
wget https://ftp.gnu.org/gnu/glibc/glibc-2.25.tar.gz
tar -xvzf glibc-2.25.tar.gz
cd glibc-2.25/
mkdir build
cd build/
../configure --prefix=/opt/local/glibc-2.25/
make -j8
make install

export LD_LIBRARY_PATH=/opt/local/glibc-2.25/lib
${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
```
