package main

import (
	"github.com/xjasonlyu/tun2socks/v2/engine"  // 引入 tun2socks 库
	"os"
	"os/exec"
)

import (
	"fyne.io/fyne/v2/app"       // 引入 fyne 库
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var key *engine.Key  // tun2socks 库的关键结构体

func init() {
	os.Setenv("FYNE_FONT", "C:\\windows\\Fonts\\simfang.ttf")  // 设置 Fyne 应用程序的字体
}

func main() {
	defer func() {  // 在 main() 函数返回时执行
		if key != nil {  // 如果有连接，关闭它
			stop()
		}
	}()

	a := app.New()  // 创建一个新的 Fyne 应用程序
	w := a.NewWindow("Tun2Socks")  // 在应用程序中创建一个新窗口
	hello := widget.NewLabel("点击按钮建立连接")  // 创建一个新的标签
	var button *widget.Button  // 声明一个指向 widget.Button 的指针
	button = widget.NewButton("开始连接", func() {  // 创建一个新的按钮，并设置其回调函数
		if key == nil {  // 如果当前没有连接，则创建一个连接
			button.SetText("断开连接")    // 将按钮文本设置为“断开连接”
			hello.SetText("已经建立连接")  // 将标签文本设置为“已经建立连接”
			run()   // 开始连接
		} else {  // 如果当前有连接，则断开连接
			button.SetText("开始连接")    // 将按钮文本设置为“开始连接”
			hello.SetText("已经断开连接")  // 将标签文本设置为“已经断开连接”
			stop()  // 断开连接
		}
	})
	w.SetContent(container.NewVBox(hello, button))  // 在窗口中添加标签和按钮
	w.ShowAndRun()  // 显示窗口并开始运行应用程序
}

func run() {
	if key != nil {
		return  // 如果已经存在连接，则退出
	}
	key = &engine.Key{
		MTU:                      0,
		Mark:                     0,
		Proxy:                    "192.168.1.1:5215",  // 连接的代理服务器IP地址和端口号
		RestAPI:                  "",
		Device:                   "tun0",
		LogLevel:                 "info",
		Interface:                "",
		TCPModerateReceiveBuffer: false,
		TCPSendBufferSize:        "",
		TCPReceiveBufferSize:     "",
		UDPTimeout:               0,
	}
	engine.Insert(key)  // 插入新的连接
	exec.Command("route", "add", "192.168.1.1", "mask", "255.255.255.255", "192.168.1.1", "metric", "5").Run()  // 添加一个路由条目
	engine.Start()  // 启动 tun2socks 服务
	exec.Command("netsh", "interface", "ip", "set", "address", "tun0", "static", "10.0.10.10", "255.255.255.0", "10.0.10.1", "3").Run()  // 设置新的 IP 地址和子网掩码
}

func stop() {
	engine.Stop()  // 停止 tun2socks 连接
	exec.Command("route", "delete", "0.0.0.0", "10.0.10.1").Run()  // 删除路由表项
	key = nil  // 删除与 tun2socks 连接有关的结构体
}