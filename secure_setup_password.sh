#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/var/lib/secure-setup"
mkdir -p "$STATE_DIR"

HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
ROLLBACK_SCRIPT="${STATE_DIR}/rollback.sh"
TIMER_PID_FILE="${STATE_DIR}/rollback.pid"
UFW_RULES_FILE="${STATE_DIR}/ufw.rules.before"
SSH_PORT_FILE="${STATE_DIR}/ssh_port"
USER_FILE="${STATE_DIR}/login_user"
EXTRA_PORTS_FILE="${STATE_DIR}/extra_ports"
KEEP22_FILE="${STATE_DIR}/keep22"

# ---------- helpers ----------
need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "请使用 root 权限运行：sudo ./${SCRIPT_NAME} [--confirm|--rollback]"
    exit 1
  fi
}

svc_reload_ssh() {
  if systemctl list-unit-files | grep -q '^ssh\.service'; then
    systemctl reload ssh || systemctl restart ssh
  elif systemctl list-unit-files | grep -q '^sshd\.service'; then
    systemctl reload sshd || systemctl restart sshd
  else
    systemctl restart ssh || systemctl restart sshd
  fi
}

write_rollback_script() {
  # 生成回滚脚本（用于自动回滚保险丝、以及手动回滚）
  cat > "$ROLLBACK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/secure-setup"
HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
UFW_RULES_FILE="${STATE_DIR}/ufw.rules.before"
TIMER_PID_FILE="${STATE_DIR}/rollback.pid"

echo "[ROLLBACK] 开始回滚..."

# 1) 还原 SSH 加固文件（直接禁用）
if [[ -f "$HARDEN_FILE" ]]; then
  mv "$HARDEN_FILE" "/root/99-hardening.conf.disabled.rollback.$(date +%F-%H%M%S)" || true
  echo "[ROLLBACK] 已禁用 SSH 加固文件：$HARDEN_FILE"
fi

# 2) 回滚 UFW（优先 restore 之前规则；否则至少 disable）
if command -v ufw >/dev/null 2>&1; then
  if [[ -s "$UFW_RULES_FILE" ]] && command -v iptables-restore >/dev/null 2>&1; then
    iptables-restore < "$UFW_RULES_FILE" || true
    echo "[ROLLBACK] 已通过 iptables-restore 还原防火墙规则（best-effort）"
    # 还原后不强制 enable/disable UFW，避免状态冲突
  else
    ufw disable || true
    echo "[ROLLBACK] 已执行：ufw disable"
  fi
fi

# 3) 重启 SSH 服务
if systemctl list-unit-files | grep -q '^ssh\.service'; then
  systemctl restart ssh || true
elif systemctl list-unit-files | grep -q '^sshd\.service'; then
  systemctl restart sshd || true
else
  systemctl restart ssh || systemctl restart sshd || true
fi
echo "[ROLLBACK] SSH 服务已重启（best-effort）"

# 4) 停止 fail2ban（避免误伤导致仍然连不上）
if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
  systemctl stop fail2ban || true
  echo "[ROLLBACK] fail2ban 已停止（best-effort）"
fi

# 5) 清理保险丝 pid 文件
rm -f "$TIMER_PID_FILE" || true

echo "[ROLLBACK] 回滚完成。"
EOF
  chmod +x "$ROLLBACK_SCRIPT"
}

set_rollback_fuse() {
  local seconds="${1:-600}"
  write_rollback_script

  # 保存当前 iptables 规则用于 best-effort restore（没有也不致命）
  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$UFW_RULES_FILE" || true
  fi

  # 启动保险丝（sleep 到点执行回滚脚本）
  nohup bash -c "sleep ${seconds}; ${ROLLBACK_SCRIPT}" >/dev/null 2>&1 &
  echo $! > "$TIMER_PID_FILE"
  echo "已设置自动回滚保险丝：${seconds} 秒后会自动回滚。"
  echo "如果你确认一切正常，请运行：sudo ./${SCRIPT_NAME} --confirm 取消保险丝。"
}

cancel_rollback_fuse() {
  if [[ -f "$TIMER_PID_FILE" ]]; then
    local pid
    pid="$(cat "$TIMER_PID_FILE" || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "已取消自动回滚保险丝（pid=${pid}）。"
    else
      echo "未找到正在运行的保险丝进程（可能已执行或已结束）。"
    fi
    rm -f "$TIMER_PID_FILE" || true
  else
    echo "没有检测到保险丝（无需取消）。"
  fi
}

do_rollback_now() {
  write_rollback_script
  echo "即将执行一键回滚..."
  bash "$ROLLBACK_SCRIPT"
}

# ---------- args ----------
need_root
if [[ "${1:-}" == "--confirm" ]]; then
  cancel_rollback_fuse
  exit 0
fi
if [[ "${1:-}" == "--rollback" ]]; then
  do_rollback_now
  exit 0
fi

# ---------- main ----------
echo "============================================"
echo "   Linux 服务器更稳加固脚本（密码登录版）"
echo " (Create User + SSH Port + UFW + Fail2Ban)"
echo " + 自动回滚保险丝 + 一键回滚"
echo "============================================"

read -rp "请输入要创建/使用的登录用户名(建议非root，如 ubuntu/debian): " LOGIN_USER
if [[ -z "${LOGIN_USER}" ]]; then
  echo "错误：用户名不能为空"
  exit 1
fi
if ! [[ "${LOGIN_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "错误：用户名格式不合法（建议小写字母/数字/下划线/短横线，且不能以数字开头）"
  exit 1
fi

read -rp "请输入新的 SSH 端口号(建议 10000-65535): " SSH_PORT
if ! [[ "${SSH_PORT}" =~ ^[0-9]+$ ]]; then
  echo "错误：端口必须是纯数字"
  exit 1
fi
if (( SSH_PORT < 10000 || SSH_PORT > 65535 )); then
  echo "错误：端口需在 10000-65535 范围"
  exit 1
fi

read -rp "是否暂时保留 22 端口放行以防锁门？(建议 yes) [yes/no]: " KEEP_PORT22
KEEP_PORT22="${KEEP_PORT22:-yes}"

read -rp "请输入需要额外放行的 TCP 端口（逗号分隔，如 80,443,8080；留空=不额外放行）: " EXTRA_PORTS

# 保存状态（便于你自己排查；回滚脚本不强依赖这些）
echo "$LOGIN_USER" > "$USER_FILE"
echo "$SSH_PORT" > "$SSH_PORT_FILE"
echo "${EXTRA_PORTS:-}" > "$EXTRA_PORTS_FILE"
echo "$KEEP_PORT22" > "$KEEP22_FILE"

echo
echo "开始处理..."
echo "（提示：脚本将先设置 10 分钟自动回滚保险丝，避免锁门）"
set_rollback_fuse 600

echo "[1/6] 创建/确认用户并设置密码..."
if ! id "${LOGIN_USER}" &>/dev/null; then
  adduser --gecos "" "${LOGIN_USER}"
else
  echo "用户 ${LOGIN_USER} 已存在。"
  read -rp "是否要为该用户重设密码？[yes/no] (默认 no): " RESET_PW
  RESET_PW="${RESET_PW:-no}"
  if [[ "${RESET_PW}" == "yes" ]]; then
    passwd "${LOGIN_USER}"
  fi
fi

echo "[2/6] 写入 SSH 加固配置（密码登录，禁用公钥）..."
mkdir -p /etc/ssh/sshd_config.d

if [[ -f "${HARDEN_FILE}" ]]; then
  cp -a "${HARDEN_FILE}" "${HARDEN_FILE}.bak.$(date +%F-%H%M%S)"
fi

cat > "${HARDEN_FILE}" <<EOF
Port ${SSH_PORT}

AllowUsers ${LOGIN_USER}
PermitRootLogin no

PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication no

X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
EOF

chmod 644 "${HARDEN_FILE}"

echo "检查 sshd 配置语法..."
if ! sshd -t; then
  echo "错误：sshd 配置检查失败，停止执行。你可直接回滚：sudo ./${SCRIPT_NAME} --rollback"
  exit 1
fi

echo "[3/6] 安装并配置 UFW 防火墙..."
apt-get update -y
apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow "${SSH_PORT}/tcp" comment "SSH new port (password login)"
if [[ "${KEEP_PORT22}" == "yes" ]]; then
  ufw allow 22/tcp comment "SSH port 22 (temporary)"
fi

if [[ -n "${EXTRA_PORTS// }" ]]; then
  IFS=',' read -ra PORT_ARR <<< "${EXTRA_PORTS}"
  for p in "${PORT_ARR[@]}"; do
    p="$(echo "$p" | tr -d ' ')"
    [[ -z "$p" ]] && continue
    if [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
      ufw allow "${p}/tcp" comment "extra tcp port"
    else
      echo "跳过非法端口：${p}"
    fi
  done
fi

ufw --force enable
ufw status verbose || true

echo "[4/6] 安装并配置 Fail2Ban..."
apt-get install -y fail2ban

cat > "/etc/fail2ban/jail.d/sshd.local" <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

echo "[5/6] 重载/重启 SSH 服务..."
svc_reload_ssh

echo "[6/6] 本机检查 SSH 监听端口..."
ss -lntp | grep -E ":(22|${SSH_PORT})\b" || true

echo "============================================"
echo "✅ 完成！"
echo "登录用户: ${LOGIN_USER}"
echo "新的 SSH 端口: ${SSH_PORT}"
echo "登录方式: 仅密码（已禁用公钥登录）"
echo "额外放行端口: ${EXTRA_PORTS:-无}"
echo "UFW 放行 22: $([[ "${KEEP_PORT22}" == "yes" ]] && echo '暂时保留(建议验证后关闭)' || echo '未放行')"
echo
echo "重要：当前已设置 10 分钟自动回滚保险丝。"
echo "请立刻新开终端测试：ssh -p ${SSH_PORT} ${LOGIN_USER}@<服务器IP>"
echo "确认一切正常后执行：sudo ./${SCRIPT_NAME} --confirm 取消保险丝"
echo "如果出现问题，可直接执行：sudo ./${SCRIPT_NAME} --rollback 一键回滚"
echo "============================================"
