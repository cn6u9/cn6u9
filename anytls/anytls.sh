#!/bin/bash
# ============================================================
# AnyTLS-Go 自动安装 + 订阅生成 + 每日端口轮换脚本
# 适用系统: Debian/Ubuntu/CentOS 等主流 Linux
# 需要 root 权限运行
# 用法:
#   ./install_anytls.sh              安装
#   ./install_anytls.sh uninstall    卸载
# ============================================================

set -e

# ---------- 可修改配置 ----------
SUB_HTTP_PORT=9119                    # 订阅 HTTP 服务监听端口
SUB_DIR="/var/www/anytls-sub"         # 订阅文件存放目录
ANYTLS_BIN="/usr/local/bin/anytls-server"
CONFIG_FILE="/etc/anytls/config.env"  # 保存端口和密码
SERVICE_FILE="/etc/systemd/system/anytls.service"
SUB_SERVICE_FILE="/etc/systemd/system/anytls-sub.service"
CRON_SCRIPT="/usr/local/bin/anytls-rotate.sh"
# ---------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------- 检查 root ----------
if [[ $EUID -ne 0 ]]; then
    log_error "请使用 root 权限运行此脚本 (sudo ./install_anytls.sh)"
    exit 1
fi

# ---------- 安装依赖 ----------
install_deps() {
    log_info "安装依赖..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq wget unzip curl cron python3 2>/dev/null
    elif command -v yum &>/dev/null; then
        yum install -y -q wget unzip curl cronie python3 2>/dev/null
        systemctl enable crond 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q wget unzip curl cronie python3 2>/dev/null
        systemctl enable crond 2>/dev/null || true
    else
        log_error "不支持的包管理器，请手动安装 wget/unzip/curl/cron/python3"
        exit 1
    fi
    log_info "依赖安装完成"
}

# ---------- 检测架构 ----------
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) log_error "不支持的架构: $arch"; exit 1 ;;
    esac
}

# ---------- 下载 anytls-server ----------
download_anytls() {
    local arch=$(detect_arch)
    log_info "检测到架构: $arch"

    # 获取最新版本 tag
    local latest_tag=$(curl -sL https://api.github.com/repos/anytls/anytls-go/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [[ -z "$latest_tag" ]]; then
        log_warn "无法获取最新版本，回退到 v0.0.13"
        latest_tag="v0.0.13"
    fi
    log_info "使用版本: $latest_tag"

    local version="${latest_tag#v}"
    local zip_name="anytls_${version}_linux_${arch}.zip"
    local download_url="https://github.com/anytls/anytls-go/releases/download/${latest_tag}/${zip_name}"

    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"

    log_info "下载 $zip_name ..."
    if ! curl -sL -o "$zip_name" "$download_url"; then
        log_error "下载失败，请检查网络"
        exit 1
    fi

    unzip -o -q "$zip_name"

    # 查找二进制文件
    local bin_path=$(find . -name "anytls-server" -type f | head -1)
    if [[ -z "$bin_path" ]]; then
        log_error "未找到 anytls-server 二进制文件"
        exit 1
    fi

    cp "$bin_path" "$ANYTLS_BIN"
    chmod +x "$ANYTLS_BIN"
    cd /
    rm -rf "$tmp_dir"
    log_info "anytls-server 已安装到 $ANYTLS_BIN"
}

# ---------- 生成随机端口和密码 ----------
generate_config() {
    local port=$(shuf -i 10000-65000 -n 1)
    local password=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)

    mkdir -p /etc/anytls
    cat > "$CONFIG_FILE" << EOF
ANYTLS_PORT=$port
ANYTLS_PASSWORD=$password
EOF
    chmod 600 "$CONFIG_FILE"

    log_info "随机端口: $port"
    log_info "随机密码: $password"
}

# ---------- 创建 anytls systemd 服务 ----------
create_service() {
    local port=$(grep ANYTLS_PORT "$CONFIG_FILE" | cut -d= -f2)
    local password=$(grep ANYTLS_PASSWORD "$CONFIG_FILE" | cut -d= -f2)

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$ANYTLS_BIN -l 0.0.0.0:$port -p $password
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable anytls
    systemctl restart anytls
    sleep 2

    if systemctl is-active --quiet anytls; then
        log_info "AnyTLS 服务已启动"
    else
        log_error "AnyTLS 服务启动失败，请检查日志: journalctl -u anytls -n 50"
        exit 1
    fi
}

# ---------- 创建订阅 HTTP systemd 服务 ----------
create_sub_service() {
    log_info "创建订阅 HTTP 服务 (systemd)..."

    # 确保目录存在
    mkdir -p "$SUB_DIR"
    touch "$SUB_DIR/index.html"   # 阻止 python http.server 列目录

    # 获取 python3 绝对路径
    local PYTHON_BIN=$(command -v python3)
    if [[ -z "$PYTHON_BIN" ]]; then
        log_error "未找到 python3，请检查依赖安装"
        exit 1
    fi

    cat > "$SUB_SERVICE_FILE" << EOF
[Unit]
Description=AnyTLS Subscription HTTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$SUB_DIR
ExecStart=$PYTHON_BIN -m http.server $SUB_HTTP_PORT --bind 0.0.0.0
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable anytls-sub
    systemctl restart anytls-sub
    sleep 1

    if systemctl is-active --quiet anytls-sub; then
        log_info "订阅 HTTP 服务已启动，端口: $SUB_HTTP_PORT"
    else
        log_error "订阅 HTTP 服务启动失败，请检查日志: journalctl -u anytls-sub -n 50"
        exit 1
    fi
}

# ---------- 生成订阅内容 ----------
generate_subscription() {
    local port=$(grep ANYTLS_PORT "$CONFIG_FILE" | cut -d= -f2)
    local password=$(grep ANYTLS_PASSWORD "$CONFIG_FILE" | cut -d= -f2)
    local ip=$(curl -s4 ifconfig.me 2>/dev/null || curl -s4 ip.sb 2>/dev/null || echo "YOUR_SERVER_IP")

    mkdir -p "$SUB_DIR"

    # AnyTLS URI 格式参考: anytls://[auth@]hostname[:port]/?
    local node_name="AnyTLS-$(date +%m%d)"
    local uri="anytls://${password}@${ip}:${port}/#${node_name}"

    # 生成纯文本订阅 (每行一个 URI)
    echo "$uri" > "$SUB_DIR/subscription-123.txt"

    # 生成 Base64 编码订阅 (部分客户端需要)
    base64 -w0 "$SUB_DIR/subscription-123.txt" > "$SUB_DIR/subscription_base64.txt"

    log_info "订阅已生成:"
    log_info "  明文地址: http://${ip}:${SUB_HTTP_PORT}/subscription-123.txt"
    log_info "  Base64地址: http://${ip}:${SUB_HTTP_PORT}/subscription_base64.txt"
    log_info "  节点 URI: $uri"
}

# ---------- 创建每日轮换脚本 ----------
create_rotate_script() {
    cat > "$CRON_SCRIPT" << 'ROTATE_EOF'
#!/bin/bash
# AnyTLS 每日端口轮换脚本

CONFIG_FILE="/etc/anytls/config.env"
SERVICE_FILE="/etc/systemd/system/anytls.service"
SUB_DIR="/var/www/anytls-sub"
ANYTLS_BIN="/usr/local/bin/anytls-server"
SUB_HTTP_PORT=9119

# 读取旧密码（保持密码不变，仅换端口）
OLD_PASSWORD=$(grep ANYTLS_PASSWORD "$CONFIG_FILE" | cut -d= -f2)
NEW_PORT=$(shuf -i 10000-65000 -n 1)

# 更新配置
cat > "$CONFIG_FILE" << EOF
ANYTLS_PORT=$NEW_PORT
ANYTLS_PASSWORD=$OLD_PASSWORD
EOF
chmod 600 "$CONFIG_FILE"

# 更新 systemd 服务
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$ANYTLS_BIN -l 0.0.0.0:$NEW_PORT -p $OLD_PASSWORD
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart anytls

# 重新生成订阅
IP=$(curl -s4 ifconfig.me 2>/dev/null || curl -s4 ip.sb 2>/dev/null || echo "YOUR_SERVER_IP")
mkdir -p "$SUB_DIR"
NODE_NAME="AnyTLS-$(date +%m%d)"
URI="anytls://${OLD_PASSWORD}@${IP}:${NEW_PORT}/#${NODE_NAME}"

echo "$URI" > "$SUB_DIR/subscription-123.txt"
base64 -w0 "$SUB_DIR/subscription-123.txt" > "$SUB_DIR/subscription_base64.txt"

# 订阅 HTTP 服务由 systemd 管理，只需重启以确保状态
systemctl restart anytls-sub

logger "AnyTLS: 端口已更换为 $NEW_PORT，订阅已更新"
ROTATE_EOF

    chmod +x "$CRON_SCRIPT"
}

# ---------- 设置 cron 任务 ----------
setup_cron() {
    local cron_line="0 2 * * * $CRON_SCRIPT"

    # 移除旧任务（如果有）
    crontab -l 2>/dev/null | grep -v "anytls-rotate.sh" | crontab - 2>/dev/null || true

    # 添加新任务
    (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
    log_info "Cron 任务已设置: 每天凌晨 2:00 自动更换端口并更新订阅"
}

# ---------- 显示信息 ----------
show_info() {
    local port=$(grep ANYTLS_PORT "$CONFIG_FILE" | cut -d= -f2)
    local password=$(grep ANYTLS_PASSWORD "$CONFIG_FILE" | cut -d= -f2)
    local ip=$(curl -s4 ifconfig.me 2>/dev/null || curl -s4 ip.sb 2>/dev/null || echo "YOUR_SERVER_IP")

    echo ""
    echo "=========================================="
    echo -e "${GREEN}  AnyTLS-Go 安装完成！${NC}"
    echo "=========================================="
    echo ""
    echo "  服务器 IP:    $ip"
    echo "  端口:         $port"
    echo "  密码:         $password"
    echo ""
    echo "  订阅地址 (明文):"
    echo "    http://${ip}:${SUB_HTTP_PORT}/subscription-123.txt"
    echo ""
    echo "  订阅地址 (Base64):"
    echo "    http://${ip}:${SUB_HTTP_PORT}/subscription_base64.txt"
    echo ""
    echo "  节点 URI:"
    echo "    anytls://${password}@${ip}:${port}/"
    echo ""
    echo "  服务管理:"
    echo "    systemctl status anytls"
    echo "    systemctl restart anytls"
    echo "    journalctl -u anytls -f"
    echo ""
    echo "    systemctl status anytls-sub"
    echo "    systemctl restart anytls-sub"
    echo "    journalctl -u anytls-sub -f"
    echo ""
    echo "  每日轮换脚本: $CRON_SCRIPT"
    echo "  配置文件:     $CONFIG_FILE"
    echo "  订阅目录:     $SUB_DIR"
    echo ""
    echo -e "${YELLOW}  注意: 请确保防火墙已放行端口 $port (TCP) 和 $SUB_HTTP_PORT (TCP)${NC}"
    echo ""
}

# ---------- 卸载 ----------
uninstall() {
    echo ""
    log_warn "即将卸载 AnyTLS-Go 及其所有配置、订阅、定时任务"
    read -r -p "确认卸载? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "已取消卸载"
        exit 0
    fi

    echo ""
    log_info "开始卸载..."

    # 1. 停止并禁用 anytls 服务
    if systemctl list-unit-files | grep -q "^anytls.service"; then
        systemctl stop anytls 2>/dev/null || true
        systemctl disable anytls 2>/dev/null || true
        log_info "已停止并禁用 anytls 服务"
    fi

    # 2. 停止并禁用 anytls-sub 服务
    if systemctl list-unit-files | grep -q "^anytls-sub.service"; then
        systemctl stop anytls-sub 2>/dev/null || true
        systemctl disable anytls-sub 2>/dev/null || true
        log_info "已停止并禁用 anytls-sub 服务"
    fi

    # 3. 删除 systemd 服务文件
    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        log_info "已删除 systemd 服务文件: $SERVICE_FILE"
    fi
    if [[ -f "$SUB_SERVICE_FILE" ]]; then
        rm -f "$SUB_SERVICE_FILE"
        log_info "已删除 systemd 服务文件: $SUB_SERVICE_FILE"
    fi
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true

    # 4. 删除二进制文件
    if [[ -f "$ANYTLS_BIN" ]]; then
        rm -f "$ANYTLS_BIN"
        log_info "已删除二进制: $ANYTLS_BIN"
    fi

    # 5. 删除订阅目录
    if [[ -d "$SUB_DIR" ]]; then
        rm -rf "$SUB_DIR"
        log_info "已删除订阅目录: $SUB_DIR"
    fi

    # 6. 删除配置目录
    if [[ -d "/etc/anytls" ]]; then
        rm -rf "/etc/anytls"
        log_info "已删除配置目录: /etc/anytls"
    fi

    # 7. 删除轮换脚本
    if [[ -f "$CRON_SCRIPT" ]]; then
        rm -f "$CRON_SCRIPT"
        log_info "已删除轮换脚本: $CRON_SCRIPT"
    fi

    # 8. 移除 cron 任务
    if crontab -l 2>/dev/null | grep -q "anytls-rotate.sh"; then
        crontab -l 2>/dev/null | grep -v "anytls-rotate.sh" | crontab - 2>/dev/null || true
        log_info "已移除 cron 定时任务"
    fi

    # 9. 清理可能的残留进程
    pkill -f "anytls-server" 2>/dev/null || true
    pkill -f "${CRON_SCRIPT}" 2>/dev/null || true
    pkill -f "http.server ${SUB_HTTP_PORT}" 2>/dev/null || true

    echo ""
    echo "=========================================="
    echo -e "${GREEN}  AnyTLS-Go 卸载完成！${NC}"
    echo "=========================================="
    echo ""
    echo -e "${YELLOW}  说明:${NC}"
    echo "    - wget/unzip/curl/cron/python3 等依赖未卸载（可能被系统其他程序使用）"
    echo "    - 如需清理依赖，请手动执行: apt-get remove wget unzip curl cron python3"
    echo "    - 本脚本文件 $(realpath "$0" 2>/dev/null || echo "$0") 未自动删除，如需可手动删除"
    echo ""
    exit 0
}

# ---------- 主流程 ----------
main() {
    # 参数解析
    case "${1:-}" in
        uninstall|remove|-u|--uninstall)
            uninstall
            ;;
        "")
            # 无参数则正常安装
            ;;
        *)
            echo "用法: $0 [uninstall]"
            echo ""
            echo "  无参数       安装 AnyTLS-Go 并配置订阅和每日轮换"
            echo "  uninstall    卸载 AnyTLS-Go 及其所有配置"
            echo ""
            exit 1
            ;;
    esac

    echo "=========================================="
    echo "  AnyTLS-Go 自动安装 + 订阅 + 每日轮换"
    echo "=========================================="
    echo ""

    install_deps
    download_anytls
    generate_config
    create_service
    create_sub_service
    generate_subscription
    create_rotate_script
    setup_cron
    show_info
}

main "$@"
