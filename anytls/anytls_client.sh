#!/bin/bash
# ============================================================
# AnyTLS 多订阅客户端管理脚本 (增强版)
#
# 功能:
#   1. 自动检测 sub.txt，不存在则创建
#   2. 自动检测 anytls-client，不存在则从 GitHub 下载编译
#   3. 从 sub.txt 读取订阅地址（每行一个）
#   4. 为每个可用订阅启动一个 anytls-client
#      本地监听端口从 127.0.0.1:7891 起递增
#   5. daemon 模式下每 3 小时重新检测
#
# 用法:
#   ./anytls-mgr.sh run      # 执行一次
#   ./anytls-mgr.sh daemon   # 守护运行，每3小时一次
#   ./anytls-mgr.sh stop     # 停止所有客户端
#   ./anytls-mgr.sh status   # 查看当前状态
# ============================================================

set -u

# ---------- 可修改配置 ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUB_FILE="${SUB_FILE:-$SCRIPT_DIR/sub.txt}"        # 订阅列表文件
CLIENT_BIN="${CLIENT_BIN:-/usr/local/bin/anytls-client}" # 客户端二进制
REPO_URL="${REPO_URL:-https://github.com/anytls/anytls-go.git}"
BASE_PORT="${BASE_PORT:-7891}"                     # 本地起始端口
CHECK_INTERVAL="${CHECK_INTERVAL:-10800}"          # 检测间隔(秒)，10800=3小时
LOG_FILE="${LOG_FILE:-/var/log/anytls-mgr.log}"
PID_DIR="${PID_DIR:-/var/run/anytls-clients}"
# --------------------------------

mkdir -p "$PID_DIR"
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="$SCRIPT_DIR/anytls-mgr.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

log() { echo -e "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }

# ============================================================
# 引导一：确保 sub.txt 存在
# ============================================================
bootstrap_sub_file() {
    if [[ -f "$SUB_FILE" ]]; then
        log "订阅文件已存在: $SUB_FILE"
        return 0
    fi

    log "${YELLOW}未检测到订阅文件，正在创建: $SUB_FILE${NC}"
    cat > "$SUB_FILE" <<'EOF'
# ============================================================
# 每行一个订阅地址，以 # 开头的行为注释
# 示例:
# https://example.com/api/v1/client/subscribe?token=xxxxx
# https://another.example.com/sub/yyyy
# ============================================================
EOF

    if [[ -f "$SUB_FILE" ]]; then
        log "${GREEN}✓ 已创建 $SUB_FILE${NC}"
        log "${YELLOW}请编辑该文件并填入订阅地址，然后重新运行脚本。${NC}"
        return 0
    else
        log "${RED}✗ 创建 $SUB_FILE 失败（权限不足？）${NC}"
        return 1
    fi
}

# ============================================================
# 引导二：确保 anytls-client 可用
# ============================================================
bootstrap_client() {
    # 1) 配置路径已经是可执行文件
    if [[ -x "$CLIENT_BIN" ]]; then
        log "已找到客户端: $CLIENT_BIN"
        return 0
    fi

    # 2) PATH 中能找到
    if command -v anytls-client >/dev/null 2>&1; then
        CLIENT_BIN="$(command -v anytls-client)"
        log "在 PATH 中找到客户端: $CLIENT_BIN"
        return 0
    fi

    # 3) 脚本目录下
    if [[ -x "$SCRIPT_DIR/anytls-client" ]]; then
        CLIENT_BIN="$SCRIPT_DIR/anytls-client"
        log "在脚本目录中找到客户端: $CLIENT_BIN"
        return 0
    fi

    log "${YELLOW}未找到 anytls-client，开始自动下载并编译...${NC}"

    # 依赖检查
    local missing=()
    command -v git >/dev/null 2>&1 || missing+=("git")
    command -v go  >/dev/null 2>&1 || missing+=("go")
    if (( ${#missing[@]} > 0 )); then
        log "${RED}✗ 缺少依赖: ${missing[*]}${NC}"
        log "  Debian/Ubuntu: apt install -y git golang-go"
        log "  CentOS/RHEL : yum install -y git golang"
        return 1
    fi

    local build_dir
    build_dir="$(mktemp -d /tmp/anytls-build.XXXXXX)"
    if [[ -z "$build_dir" || ! -d "$build_dir" ]]; then
        log "${RED}✗ 无法创建临时目录${NC}"
        return 1
    fi

    # 清理函数
    _cleanup_build() { rm -rf "$build_dir"; }

    log "克隆仓库: $REPO_URL"
    if ! git clone --depth 1 "$REPO_URL" "$build_dir/anytls-go" >>"$LOG_FILE" 2>&1; then
        log "${RED}✗ git clone 失败，请检查网络或代理${NC}"
        _cleanup_build
        return 1
    fi

    log "编译 anytls-client ..."
    local built_bin=""
    local src_dir="$build_dir/anytls-go"

    # 常见的构建入口
    if [[ -d "$src_dir/cmd/client" ]]; then
        if (cd "$src_dir" && go build -o "$build_dir/anytls-client" ./cmd/client) >>"$LOG_FILE" 2>&1; then
            built_bin="$build_dir/anytls-client"
        fi
    fi

    # 回退：搜索包含 client 的 main.go
    if [[ -z "$built_bin" ]]; then
        local candidate
        candidate=$(grep -rl --include="main.go" -E "anytls-client|package main" "$src_dir" 2>/dev/null \
                    | grep -i client | head -1 || true)
        if [[ -n "$candidate" ]]; then
            local pkg_dir
            pkg_dir="$(dirname "$candidate")"
            if (cd "$src_dir" && go build -o "$build_dir/anytls-client" "./${pkg_dir#$src_dir/}") >>"$LOG_FILE" 2>&1; then
                built_bin="$build_dir/anytls-client"
            fi
        fi
    fi

    if [[ -z "$built_bin" || ! -x "$built_bin" ]]; then
        log "${RED}✗ 编译失败，请查看日志: $LOG_FILE${NC}"
        _cleanup_build
        return 1
    fi

    # 安装到目标路径，无权限则退回脚本目录
    if install -m 0755 "$built_bin" "$CLIENT_BIN" 2>/dev/null; then
        log "${GREEN}✓ 已安装客户端到 $CLIENT_BIN${NC}"
    else
        local fallback="$SCRIPT_DIR/anytls-client"
        if install -m 0755 "$built_bin" "$fallback" 2>/dev/null; then
            CLIENT_BIN="$fallback"
            log "${YELLOW}无权限写入 $CLIENT_BIN，已安装到 $fallback${NC}"
        else
            log "${RED}✗ 安装客户端失败${NC}"
            _cleanup_build
            return 1
        fi
    fi

    _cleanup_build
    return 0
}

# ============================================================
# 停止所有由本脚本启动的客户端
# ============================================================
stop_all_clients() {
    if [[ -d "$PID_DIR" ]]; then
        for pidfile in "$PID_DIR"/*.pid; do
            [[ -f "$pidfile" ]] || continue
            local pid
            pid=$(cat "$pidfile" 2>/dev/null || true)
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
            rm -f "$pidfile"
        done
    fi
    pkill -f "$CLIENT_BIN" 2>/dev/null || true
    sleep 0.5
}

# ============================================================
# 拉取订阅，返回 anytls://...
# ============================================================
fetch_subscription() {
    local url="$1"
    local content
    content=$(curl -sL --max-time 15 "$url" 2>/dev/null) || return 1
    [[ -z "$content" ]] && return 1

    if echo "$content" | grep -q "anytls://"; then
        echo "$content" | grep -oE "anytls://[^[:space:]]+" | head -1
        return 0
    fi

    local decoded
    decoded=$(printf '%s' "$content" | base64 -d 2>/dev/null || true)
    if echo "$decoded" | grep -q "anytls://"; then
        echo "$decoded" | grep -oE "anytls://[^[:space:]]+" | head -1
        return 0
    fi
    return 1
}

# ============================================================
# 解析 anytls URI: anytls://password@host:port/#name
# ============================================================
parse_uri() {
    local uri="$1"
    local rest="${uri#anytls://}"
    rest="${rest%%#*}"
    rest="${rest%%/*}"
    local password="${rest%@*}"
    local hostport="${rest##*@}"
    local host="${hostport%:*}"
    local port="${hostport##*:}"
    printf '%s|%s|%s\n' "$password" "$host" "$port"
}

# ============================================================
# 单次执行
# ============================================================
run_once() {
    log "==================== 开始检查订阅 ===================="
    stop_all_clients

    if [[ ! -f "$SUB_FILE" ]]; then
        log "${RED}错误: 找不到订阅文件 $SUB_FILE${NC}"
        return 1
    fi

    local idx=0 ok=0 fail=0

    while IFS= read -r url || [[ -n "$url" ]]; do
        url=$(echo "$url" | tr -d ' \r\t')
        [[ -z "$url" ]] && continue
        [[ "$url" == \#* ]] && continue

        idx=$((idx + 1))
        local local_port=$((BASE_PORT + idx - 1))

        log "[$idx] 订阅: $url"

        local uri
        if ! uri=$(fetch_subscription "$url"); then
            log "     ${RED}✗ 订阅不可用或无法解析${NC}"
            fail=$((fail + 1))
            continue
        fi

        local parsed password host port
        parsed=$(parse_uri "$uri")
        password="${parsed%%|*}"
        local rest="${parsed#*|}"
        host="${rest%%|*}"
        port="${rest##*|}"

        if [[ -z "$password" || -z "$host" || -z "$port" ]]; then
            log "     ${RED}✗ 解析失败: $uri${NC}"
            fail=$((fail + 1))
            continue
        fi

        log "     ${GREEN}✓ 节点: $host:$port${NC}  密码: $password"
        log "     命令: $CLIENT_BIN -l 127.0.0.1:$local_port -s $host:$port -p $password"

        nohup "$CLIENT_BIN" \
            -l "127.0.0.1:$local_port" \
            -s "$host:$port" \
            -p "$password" \
            >> "${LOG_FILE}.client.${local_port}" 2>&1 &
        local pid=$!
        echo "$pid" > "$PID_DIR/client_${local_port}.pid"

        sleep 0.5
        if kill -0 "$pid" 2>/dev/null; then
            log "     ${GREEN}→ 已启动客户端 PID=$pid，监听 127.0.0.1:$local_port${NC}"
            ok=$((ok + 1))
        else
            log "     ${RED}✗ 客户端启动失败（详见 ${LOG_FILE}.client.${local_port}）${NC}"
            rm -f "$PID_DIR/client_${local_port}.pid"
            fail=$((fail + 1))
        fi
    done < "$SUB_FILE"

    log "==================== 完成: 成功 $ok 个, 失败 $fail 个 ===================="
}

# ============================================================
# 守护模式
# ============================================================
daemon_loop() {
    log "守护模式启动，检查间隔 $((CHECK_INTERVAL / 3600)) 小时"
    while true; do
        run_once || true
        log "下次检查将在 $((CHECK_INTERVAL / 3600)) 小时后"
        sleep "$CHECK_INTERVAL"
    done
}

# ============================================================
# 主入口
# ============================================================
case "${1:-run}" in
    run|daemon)
        # 引导：确保订阅文件和客户端可用
        bootstrap_sub_file || exit 1
        bootstrap_client    || exit 1

        # 检查订阅文件是否为空（仅有注释）
        if ! grep -qE '^[^#[:space:]]' "$SUB_FILE" 2>/dev/null; then
            log "${YELLOW}警告: $SUB_FILE 中没有任何订阅地址，请先编辑该文件。${NC}"
            exit 1
        fi

        if [[ "${1}" == "daemon" ]]; then
            daemon_loop
        else
            run_once
        fi
        ;;
    stop)
        stop_all_clients
        log "已停止所有 anytls-client"
        ;;
    status)
        echo "=== 运行中的 anytls-client 进程 ==="
        pgrep -af "anytls-client" || echo "无运行中的客户端"
        echo ""
        echo "=== 本地监听端口 ==="
        ss -tlnp 2>/dev/null | grep -E "127\.0\.0\.1:78[0-9][0-9]" || echo "无监听端口"
        echo ""
        echo "=== PID 文件 ==="
        ls -la "$PID_DIR" 2>/dev/null || true
        ;;
    *)
        echo "用法: $0 {run|daemon|stop|status}"
        exit 1
        ;;
esac
