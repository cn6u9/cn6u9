### 安装编译环境
```
#!/bin/bash

# 安装系统依赖
echo "安装系统依赖..."
if command -v apt-get &> /dev/null; then
    sudo apt-get install -y libgl1-mesa-dev xorg-dev mingw-w64 build-essential
elif command -v yum &> /dev/null; then
    sudo yum install -y mesa-libGL-devel libXcursor-devel libXrandr-devel libXinerama-devel libXi-devel
else
    echo "无法识别的Linux发行版，请手动安装OpenGL开发包"
    exit 1
fi

# 初始化go模块
echo "初始化go模块..."
cat > go.mod << 'EOL'
module tun2socks-gui

go 1.22

require (
    fyne.io/fyne/v2 v2.4.3
    github.com/xjasonlyu/tun2socks/v2 v2.5.0
)
EOL

# 下载依赖
echo "下载Go依赖..."
go mod tidy

# 修复可能的GLFW问题
echo "检查GLFW配置..."
go get -u github.com/go-gl/glfw/v3.3/glfw

echo "安装完成！现在可以运行程序了"
```
### build
```
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build
```
