#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/var/lib/secure-setup"
mkdir -p "$STATE_DIR"

MAIN_SSHD_CONFIG="/etc/ssh/sshd_config"
MAIN_SSHD_BACKUP="${STATE_DIR}/sshd_config.before"

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
    echo "请使用 root 权限运行：sudo ./${SCRIPT_NAME} [--confirm [--keep-allowusers] | --rollback]"
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

ensure_sshd_include_dir() {
  # 最稳：把 Include 放到 sshd_config 顶部（避免放到 Match block 后面）
  local include_line="Include /etc/ssh/sshd_config.d/*.conf"
  if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$' "$MAIN_SSHD_CONFIG"; then
    return 0
  fi

  echo "[INFO] 检测到 $MAIN_SSHD_CONFIG 未启用 sshd_config.d，正在在文件顶部插入 Include..."
  cp -a "$MAIN_SSHD_CONFIG" "$MAIN_SSHD_BACKUP"

  local tmp
  tmp="$(mktemp)"
  {
    echo "$include_line"
    cat "$MAIN_SSHD_CONFIG"
  } > "$tmp"
  cat "$tmp" > "$MAIN_SSHD_CONFIG"
  rm -f "$tmp"
}

write_rollback_script() {
  cat > "$ROLLBACK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/secure-setup"
HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
UFW_RULES_FILE="${STATE_DIR}/ufw.rules.before"
TIMER_PID_FILE="${STATE_DIR}/rollback.pid"
MAIN_SSHD_CONFIG="/etc/ssh/sshd_config"
MAIN_SSHD_BACKUP="${STATE_DIR}/sshd_config.before"

echo "[ROLLBACK] 开始回滚..."

# 1) 禁用 SSH 加固文件
if [[ -f "$HARDEN_FILE" ]]; then
  mv "$HARDEN_FILE" "/root/99-hardening.conf.disabled.rollback.$(date +%F-%H%M%S)" || true
  echo "[ROLLBACK] 已禁用 SSH 加固文件：$HARDEN_FILE"
fi

# 2) 恢复主 sshd_config（撤销脚本插入的 Include）
if [[ -f "$MAIN_SSHD_BACKUP" ]]; then
  cp -a "$MAIN_SSHD_BACKUP" "$MAIN_SSHD_CONFIG" || true
  echo "[ROLLBACK] 已恢复主 SSH 配置：$MAIN_SSHD_CONFIG"
fi

# 3) 回滚/放开防火墙
if command -v ufw >/dev/null 2>&1; then
  if [[ -s "$UFW_RULES_FILE" ]] && command -v iptables-restore >/dev/null 2>&1; then
    iptables-restore < "$UFW_RULES_FILE" || true
    echo "[ROLLBACK] 已通过 iptables-restore 还原防火墙规则（best-effort）"
  else
    ufw disable || true
    echo "[ROLLBACK] 已执行：ufw disable"
  fi
fi

# 4) 重启 SSH 服务
if systemctl list-unit-files | grep -q '^ssh\.service'; then
  systemctl restart ssh || true
elif systemctl list-unit-files | grep -q '^sshd\.service'; then
  systemctl restart sshd || true
else
  systemctl restart ssh || systemctl restart sshd || true
fi
echo "[ROLLBACK] SSH 服务已重启（best-effort）"

# 5) 停止 fail2ban（避免误伤）
if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
  systemctl stop fail2ban || true
  echo "[ROLLBACK] fail2ban 已停止（best-effort）"
fi

# 6) 清理保险丝 pid 文件
rm -f "$TIMER_PID_FILE" || true

echo "[ROLLBACK] 回滚完成。"
EOF
  chmod +x "$ROLLBACK_SCRIPT"
}

set_rollback_fuse() {
  local seconds="${1:-600}"
  write_rollback_script

  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$UFW_RULES_FILE" || true
  fi

  nohup bash -c "sleep ${seconds}; ${ROLLBACK_SCRIPT}" >/dev/null 2>&1 &
  echo $! > "$TIMER_PID_FILE"
  echo "已设置自动回滚保险丝：${seconds} 秒后会自动回滚。"
  echo "确认一切正常后运行：sudo ./${SCRIPT_NAME} --confirm"
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

valid_username_or_exit() {
  local u="$1"
  if [[ -z "$u" ]]; then
    echo "错误：用户名不能为空"
    exit 1
  fi
  if ! [[ "$u" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo "错误：用户名格式不合法（建议小写字母/数字/下划线/短横线，且不能以数字开头）"
    exit 1
  fi
}

valid_port_or_exit() {
  local p="$1"
  if ! [[ "$p" =~ ^[0-9]+$ ]]; then
    echo "错误：端口必须是纯数字"
    exit 1
  fi
  if (( p < 1 || p > 65535 )); then
    echo "错误：端口需在 1-65535 范围"
    exit 1
  fi
}

compute_allowusers_merge() {
  local existing
  existing="$(
    sshd -T 2>/dev/null | awk '$1=="allowusers"{for(i=2;i<=NF;i++) print $i}' | sort -u
  )"
  printf "%s\n%s\n" "$existing" "$1" | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

apply_harden_file() {
  local ssh_port="$1"
  local allow_users="$2"

  mkdir -p /etc/ssh/sshd_config.d

  if [[ -f "${HARDEN_FILE}" ]]; then
    cp -a "${HARDEN_FILE}" "${HARDEN_FILE}.bak.$(date +%F-%H%M%S)"
  fi

  cat > "${HARDEN_FILE}" <<EOF
Port ${ssh_port}

# 合并模式：避免把已有可登录用户踢出门
AllowUsers ${allow_users}

# 禁止 root 直接登录（如需暂时保留 root，请自行改回）
PermitRootLogin no

# 密码登录 + 禁用公钥
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication no

# 基础加固
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
EOF

  chmod 644 "${HARDEN_FILE}"
}

assert_sshd_listening_port() {
  local expected="$1"

  # 最可靠：只要看到 ":expected" 且进程是 sshd 就算通过
  if ss -lntp 2>/dev/null | awk -v p=":$expected" '
      $1=="LISTEN" && index($4,p)>0 && $0 ~ /users:\(\("sshd"/ { ok=1 }
      END { exit(ok?0:1) }
    '; then
    return 0
  fi

  echo "错误：未检测到 sshd 在监听端口 ${expected}。"
  echo "调试信息："
  ss -lntp | grep sshd || true
  sshd -T 2>/dev/null | awk '$1=="port"{print}' || true
  exit 1
}


# ---------- args ----------
need_root

if [[ "${1:-}" == "--confirm" ]]; then
  KEEP_ALLOWUSERS="no"
  if [[ "${2:-}" == "--keep-allowusers" ]]; then
    KEEP_ALLOWUSERS="yes"
  fi

  cancel_rollback_fuse

  if [[ ! -f "$USER_FILE" ]]; then
    echo "没有找到上次运行的状态文件：$USER_FILE"
    exit 1
  fi

  LOGIN_USER="$(cat "$USER_FILE")"
  valid_username_or_exit "$LOGIN_USER"

  if [[ "$KEEP_ALLOWUSERS" != "yes" ]]; then
    echo "[CONFIRM] 正在收紧 AllowUsers -> 仅允许：${LOGIN_USER}"
    ensure_sshd_include_dir
    apply_harden_file "$(cat "$SSH_PORT_FILE" 2>/dev/null || echo 22)" "${LOGIN_USER}"
    sshd -t
    svc_reload_ssh
  else
    echo "[CONFIRM] 保持 AllowUsers 合并模式不变（未收紧）。"
  fi

  echo "[CONFIRM] 完成。"
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
valid_username_or_exit "$LOGIN_USER"

read -rp "请输入新的 SSH 端口号(建议 10000-65535): " SSH_PORT
valid_port_or_exit "$SSH_PORT"
if (( SSH_PORT < 10000 || SSH_PORT > 65535 )); then
  echo "提示：建议使用 10000-65535 的高位端口。"
fi

read -rp "是否暂时保留 22 端口放行以防锁门？(建议 yes) [yes/no]: " KEEP_PORT22
KEEP_PORT22="${KEEP_PORT22:-yes}"

read -rp "请输入需要额外放行的 TCP 端口（逗号分隔，如 80,443,2334；留空=不额外放行）: " EXTRA_PORTS

echo "$LOGIN_USER" > "$USER_FILE"
echo "$SSH_PORT" > "$SSH_PORT_FILE"
echo "${EXTRA_PORTS:-}" > "$EXTRA_PORTS_FILE"
echo "$KEEP_PORT22" > "$KEEP22_FILE"

echo
echo "开始处理..."
echo "（提示：脚本将先设置 10 分钟自动回滚保险丝，避免锁门）"
set_rollback_fuse 600

echo "[0/6] 确保 sshd_config.d 生效..."
ensure_sshd_include_dir

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
MERGED_ALLOW_USERS="$(compute_allowusers_merge "$LOGIN_USER")"
apply_harden_file "$SSH_PORT" "$MERGED_ALLOW_USERS"

echo "检查 sshd 配置语法..."
sshd -t

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

echo "[5.5/6] 校验 sshd 是否真的监听新端口..."
assert_sshd_listening_port "$SSH_PORT"

echo "[6/6] 本机检查 SSH 监听端口..."
ss -lntp | grep -E ":(22|${SSH_PORT})\b" || true

echo "============================================"
echo "✅ 完成！"
echo "登录用户: ${LOGIN_USER}"
echo "新的 SSH 端口: ${SSH_PORT}"
echo "登录方式: 仅密码（已禁用公钥登录）"
echo "AllowUsers(当前合并模式): ${MERGED_ALLOW_USERS}"
echo "额外放行端口: ${EXTRA_PORTS:-无}"
echo "UFW 放行 22: $([[ "${KEEP_PORT22}" == "yes" ]] && echo '暂时保留(建议验证后关闭)' || echo '未放行')"
echo
echo "重要：当前已设置 10 分钟自动回滚保险丝。"
echo "请立刻新开终端测试：ssh -p ${SSH_PORT} ${LOGIN_USER}@<服务器IP>"
echo "确认一切正常后执行：sudo ./${SCRIPT_NAME} --confirm （默认会收紧 AllowUsers 只留 ${LOGIN_USER}）"
echo "如不想收紧 AllowUsers：sudo ./${SCRIPT_NAME} --confirm --keep-allowusers"
echo "如果出现问题，可直接执行：sudo ./${SCRIPT_NAME} --rollback 一键回滚"
echo "============================================"
