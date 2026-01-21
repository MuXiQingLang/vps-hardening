#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/var/lib/secure-setup"
mkdir -p "$STATE_DIR"

MAIN_SSHD_CONFIG="/etc/ssh/sshd_config"
MAIN_SSHD_BACKUP="${STATE_DIR}/sshd_config.before"

HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
ROLLBACK_SCRIPT="${STATE_DIR}/rollback.sh"
ROLLBACK_UNIT_FILE="${STATE_DIR}/rollback.unit"
ROLLBACK_LOG="/var/log/secure-setup.log"
UFW_RULES_FILE="${STATE_DIR}/ufw.rules.before"

SSH_PORT_FILE="${STATE_DIR}/ssh_port"
USER_FILE="${STATE_DIR}/login_user"
EXTRA_PORTS_FILE="${STATE_DIR}/extra_ports"
KEEP22_FILE="${STATE_DIR}/keep22"

KEYS_ENABLED_FILE="${STATE_DIR}/keys_enabled"
KEYS_FILE="${STATE_DIR}/keys"  # 记录本次输入的公钥（便于审计/排查）

# ---------------- logging ----------------
log_init() {
  touch "$ROLLBACK_LOG" 2>/dev/null || true
  chmod 600 "$ROLLBACK_LOG" 2>/dev/null || true
}
logi() { log_init; echo "[$1] $(date -Is) $2" >> "$ROLLBACK_LOG" 2>/dev/null || true; }

# ---------------- helpers ----------------
need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "请使用 root 权限运行：sudo ./${SCRIPT_NAME} [--confirm [--disable-password] [--disable-22] | --rollback]"
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
  local include_line="Include /etc/ssh/sshd_config.d/*.conf"
  if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$' "$MAIN_SSHD_CONFIG"; then
    return 0
  fi

  echo "[INFO] 检测到 $MAIN_SSHD_CONFIG 未启用 sshd_config.d，正在在文件顶部插入 Include..."
  cp -a "$MAIN_SSHD_CONFIG" "$MAIN_SSHD_BACKUP"
  logi "INFO" "insert Include into $MAIN_SSHD_CONFIG, backup=$MAIN_SSHD_BACKUP"

  local tmp
  tmp="$(mktemp)"
  {
    echo "$include_line"
    cat "$MAIN_SSHD_CONFIG"
  } > "$tmp"
  cat "$tmp" > "$MAIN_SSHD_CONFIG"
  rm -f "$tmp"
}

neutralize_cloudimg_passwordauth() {
  local f="/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"
  if [[ -f "$f" ]] && grep -qE '^\s*PasswordAuthentication\s+no\b' "$f"; then
    echo "[INFO] 检测到 cloudimg 默认禁用密码登录：$f，正在注释该行以避免覆盖..."
    cp -a "$f" "${f}.bak.$(date +%F-%H%M%S)"
    sed -i 's/^\s*PasswordAuthentication\s\+no\b/# PasswordAuthentication no (disabled by hardening script)/' "$f"
    logi "INFO" "neutralized cloudimg PasswordAuthentication no in $f"
  fi
}

write_rollback_script() {
  cat > "$ROLLBACK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/secure-setup"
HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
UFW_RULES_FILE="${STATE_DIR}/ufw.rules.before"
MAIN_SSHD_CONFIG="/etc/ssh/sshd_config"
MAIN_SSHD_BACKUP="${STATE_DIR}/sshd_config.before"
ROLLBACK_LOG="/var/log/secure-setup.log"

touch "$ROLLBACK_LOG" 2>/dev/null || true
chmod 600 "$ROLLBACK_LOG" 2>/dev/null || true
echo "[ROLLBACK] $(date -Is) triggered user=$(id -un) pid=$$ ppid=$PPID" >> "$ROLLBACK_LOG"
echo "[ROLLBACK] start" >> "$ROLLBACK_LOG"

if [[ -f "$HARDEN_FILE" ]]; then
  mv "$HARDEN_FILE" "/root/99-hardening.conf.disabled.rollback.$(date +%F-%H%M%S)" || true
  echo "[ROLLBACK] disabled $HARDEN_FILE" >> "$ROLLBACK_LOG"
fi

if [[ -f "$MAIN_SSHD_BACKUP" ]]; then
  cp -a "$MAIN_SSHD_BACKUP" "$MAIN_SSHD_CONFIG" || true
  echo "[ROLLBACK] restored $MAIN_SSHD_CONFIG from backup" >> "$ROLLBACK_LOG"
fi

if command -v ufw >/dev/null 2>&1; then
  if [[ -s "$UFW_RULES_FILE" ]] && command -v iptables-restore >/dev/null 2>&1; then
    iptables-restore < "$UFW_RULES_FILE" || true
    echo "[ROLLBACK] iptables-restore applied" >> "$ROLLBACK_LOG"
  else
    ufw disable || true
    echo "[ROLLBACK] ufw disabled" >> "$ROLLBACK_LOG"
  fi
fi

if systemctl list-unit-files | grep -q '^ssh\.service'; then
  systemctl restart ssh || true
elif systemctl list-unit-files | grep -q '^sshd\.service'; then
  systemctl restart sshd || true
else
  systemctl restart ssh || systemctl restart sshd || true
fi
echo "[ROLLBACK] ssh restarted" >> "$ROLLBACK_LOG"

if systemctl list-unit-files | grep -q '^fail2ban\.service'; then
  systemctl stop fail2ban || true
  echo "[ROLLBACK] fail2ban stopped" >> "$ROLLBACK_LOG"
fi

echo "[ROLLBACK] done" >> "$ROLLBACK_LOG"
EOF
  chmod +x "$ROLLBACK_SCRIPT"
}

cancel_rollback_fuse() {
  if [[ -f "$ROLLBACK_UNIT_FILE" ]]; then
    local unit
    unit="$(cat "$ROLLBACK_UNIT_FILE" 2>/dev/null || true)"
    if [[ -n "${unit:-}" ]]; then
      systemctl stop "$unit" 2>/dev/null || true
      systemctl reset-failed "$unit" 2>/dev/null || true
      echo "已取消自动回滚保险丝（unit=${unit}）。"
      logi "CONFIRM" "canceled unit=${unit} user=$(id -un) pid=$$"
    fi
    rm -f "$ROLLBACK_UNIT_FILE" || true
  else
    echo "没有检测到保险丝（无需取消）。"
  fi
}

set_rollback_fuse() {
  local seconds="${1:-600}"
  write_rollback_script

  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$UFW_RULES_FILE" || true
  fi

  cancel_rollback_fuse || true

  local unit="secure-setup-rollback-$(date +%s)"
  echo "$unit" > "$ROLLBACK_UNIT_FILE"
  systemd-run --quiet --unit "$unit" --on-active="${seconds}s" /usr/bin/env bash "$ROLLBACK_SCRIPT"

  logi "INFO" "armed rollback fuse unit=${unit} seconds=${seconds} user=$(id -un) pid=$$"
  echo "已设置自动回滚保险丝：${seconds} 秒后会自动回滚。"
  echo "确认一切正常后运行：sudo ./${SCRIPT_NAME} --confirm 取消保险丝。"
}

do_rollback_now() {
  write_rollback_script
  echo "即将执行一键回滚..."
  logi "INFO" "manual rollback invoked user=$(id -un) pid=$$"
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
  local password_auth="$3"   # yes/no
  local pubkey_auth="$4"     # yes/no
  local kbdint_auth="$5"     # yes/no

  mkdir -p /etc/ssh/sshd_config.d
  if [[ -f "${HARDEN_FILE}" ]]; then
    cp -a "${HARDEN_FILE}" "${HARDEN_FILE}.bak.$(date +%F-%H%M%S)"
  fi

  cat > "${HARDEN_FILE}" <<EOF
Port ${ssh_port}

# 合并模式：避免把已有可登录用户踢出门
AllowUsers ${allow_users}

PermitRootLogin no

PasswordAuthentication ${password_auth}
PubkeyAuthentication ${pubkey_auth}
KbdInteractiveAuthentication ${kbdint_auth}
ChallengeResponseAuthentication no
UsePAM yes

X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
EOF

  chmod 644 "${HARDEN_FILE}"
  logi "INFO" "wrote harden file $HARDEN_FILE port=$ssh_port allowusers='$allow_users' password=$password_auth pubkey=$pubkey_auth kbdint=$kbdint_auth"
}

assert_sshd_listening_port() {
  local expected="$1"
  if ss -lnt 2>/dev/null | awk -v p=":${expected}" '$1=="LISTEN" && index($4,p)>0 {ok=1} END{exit(ok?0:1)}'; then
    return 0
  fi

  echo "错误：未检测到端口 ${expected} 处于 LISTEN。"
  echo "调试信息："
  ss -lntp | grep -E "(:${expected}\b|sshd)" || true
  sshd -T 2>/dev/null | awk '$1=="port"{print}' || true
  exit 1
}

grant_sudo_privilege() {
  local u="$1"
  echo "[1.5/6] 赋予 ${u} sudo 权限（需要密码，不是免密）..."
  usermod -aG sudo "${u}" || true
  local f="/etc/sudoers.d/90-${u}"
  echo "${u} ALL=(ALL:ALL) ALL" > "$f"
  chmod 440 "$f"
  visudo -cf /etc/sudoers
  logi "INFO" "granted sudo to user=$u via group sudo and /etc/sudoers.d/90-$u"
}

read_ssh_keys_multiline() {
  local out_file="$1"
  : > "$out_file"

  echo
  echo "现在输入要授权给该用户的 SSH 公钥（可多行粘贴）。"
  echo "输入完成后，单独输入一行 END 结束："

  while IFS= read -r line; do
    [[ "${line}" == "END" ]] && break
    [[ -z "${line// }" ]] && continue
    echo "${line}" >> "$out_file"
  done

  [[ -s "$out_file" ]]
}

install_authorized_keys() {
  local login_user="$1"
  local keys_file="$2"

  local user_home
  user_home="$(eval echo "~${login_user}")"
  local ssh_dir="${user_home}/.ssh"
  local auth_keys="${ssh_dir}/authorized_keys"

  echo "[KEYS] 写入 ${login_user} 的 authorized_keys..."
  install -d -m 700 -o "${login_user}" -g "${login_user}" "${ssh_dir}"
  touch "${auth_keys}"
  chown "${login_user}:${login_user}" "${auth_keys}"
  chmod 600 "${auth_keys}"

  while IFS= read -r k; do
    [[ -z "${k// }" ]] && continue
    if [[ "${k}" =~ ^ssh-(rsa|ed25519|ecdsa)[[:space:]]+ ]]; then
      if ! grep -Fqx "${k}" "${auth_keys}"; then
        echo "${k}" >> "${auth_keys}"
      fi
    else
      echo "[KEYS] 警告：跳过一行不符合 ssh key 形式的内容：${k}"
    fi
  done < "${keys_file}"

  echo "[KEYS] 已写入：${auth_keys}"
  logi "INFO" "authorized_keys updated for user=$login_user file=$auth_keys"
}

confirm_edit_allowusers() {
  local allow_users_final="$1"

  if [[ ! -f "$HARDEN_FILE" ]]; then
    echo "错误：$HARDEN_FILE 不存在。为避免误操作（例如端口被改回 22），confirm 已停止。"
    exit 1
  fi

  if grep -qE '^\s*AllowUsers\s+' "$HARDEN_FILE"; then
    sed -i -E "s/^\s*AllowUsers\s+.*/AllowUsers ${allow_users_final}/" "$HARDEN_FILE"
  else
    printf "\nAllowUsers %s\n" "$allow_users_final" >> "$HARDEN_FILE"
  fi

  logi "CONFIRM" "set AllowUsers in $HARDEN_FILE to '$allow_users_final' (no port change)"
}

confirm_sync_main_allowusers() {
  local allow_users_final="$1"

  if [[ ! -f "$MAIN_SSHD_CONFIG" ]]; then
    echo "警告：$MAIN_SSHD_CONFIG 不存在，跳过同步主配置 AllowUsers。"
    logi "WARN" "main sshd_config missing; cannot sync AllowUsers"
    return 0
  fi

  if grep -qE '^\s*AllowUsers\s+' "$MAIN_SSHD_CONFIG"; then
    local b="${STATE_DIR}/sshd_config.before.confirm_allowusers.$(date +%F-%H%M%S)"
    cp -a "$MAIN_SSHD_CONFIG" "$b"
    sed -i -E "s/^\s*AllowUsers\s+.*/AllowUsers ${allow_users_final}/" "$MAIN_SSHD_CONFIG"
    logi "CONFIRM" "synced AllowUsers in $MAIN_SSHD_CONFIG to '$allow_users_final' backup=$b"
  else
    echo "" >> "$MAIN_SSHD_CONFIG"
    echo "AllowUsers ${allow_users_final}" >> "$MAIN_SSHD_CONFIG"
    logi "CONFIRM" "appended AllowUsers to $MAIN_SSHD_CONFIG value='$allow_users_final'"
  fi
}

confirm_disable_password_only() {
  if [[ ! -f "$HARDEN_FILE" ]]; then
    echo "错误：$HARDEN_FILE 不存在，无法安全关闭密码登录。"
    exit 1
  fi

  if grep -qE '^\s*PubkeyAuthentication\s+' "$HARDEN_FILE"; then
    sed -i -E 's/^\s*PubkeyAuthentication\s+.*/PubkeyAuthentication yes/' "$HARDEN_FILE"
  else
    echo "PubkeyAuthentication yes" >> "$HARDEN_FILE"
  fi

  if grep -qE '^\s*PasswordAuthentication\s+' "$HARDEN_FILE"; then
    sed -i -E 's/^\s*PasswordAuthentication\s+.*/PasswordAuthentication no/' "$HARDEN_FILE"
  else
    echo "PasswordAuthentication no" >> "$HARDEN_FILE"
  fi

  if grep -qE '^\s*KbdInteractiveAuthentication\s+' "$HARDEN_FILE"; then
    sed -i -E 's/^\s*KbdInteractiveAuthentication\s+.*/KbdInteractiveAuthentication no/' "$HARDEN_FILE"
  else
    echo "KbdInteractiveAuthentication no" >> "$HARDEN_FILE"
  fi

  logi "CONFIRM" "disabled password auth (no port change)"
}

confirm_disable_22() {
  echo "[CONFIRM] 正在关闭 22 端口（UFW + sshd 监听）..."

  if [[ ! -f "$HARDEN_FILE" ]] || ! grep -qE '^\s*Port\s+' "$HARDEN_FILE"; then
    echo "错误：$HARDEN_FILE 缺失或没有 Port 行，无法安全关闭 22。"
    exit 1
  fi
  if grep -qE '^\s*Port\s+22\b' "$HARDEN_FILE"; then
    echo "错误：检测到 $HARDEN_FILE 仍包含 Port 22，拒绝关闭 22（避免误判）。"
    exit 1
  fi

  if command -v ufw >/dev/null 2>&1; then
    local nums
    nums="$(
      ufw status numbered 2>/dev/null | awk '
        match($0,/^\[[[:space:]]*([0-9]+)\]/,m) && $0 ~ /(^|[[:space:]])22\/tcp([[:space:]]|$)/ {print m[1]}
      ' | sort -rn
    )"
    if [[ -n "${nums}" ]]; then
      while IFS= read -r n; do
        [[ -z "$n" ]] && continue
        ufw --force delete "$n" || true
      done <<< "$nums"
      logi "CONFIRM" "ufw removed allow rules for 22/tcp (numbers: ${nums//$'\n'/,})"
    fi
  fi

  if grep -qE '^\s*Port\s+22\b' "$MAIN_SSHD_CONFIG"; then
    local b="${STATE_DIR}/sshd_config.before.confirm_disable22.$(date +%F-%H%M%S)"
    cp -a "$MAIN_SSHD_CONFIG" "$b"
    sed -i -E 's/^\s*Port\s+22\b/# Port 22 (disabled by --disable-22)/' "$MAIN_SSHD_CONFIG"
    logi "CONFIRM" "commented Port 22 in $MAIN_SSHD_CONFIG backup=$b"
  fi
}

# ---------------- args ----------------
need_root

if [[ "${1:-}" == "--confirm" ]]; then
  # confirm 只支持：收紧 + 可选关密码 + 可选关 22
  DISABLE_PASSWORD="no"
  DISABLE_22="no"
  KEEP_ALLOWUSERS="no"  # 兼容旧参数，但会被忽略

  for a in "${@:2}"; do
    case "$a" in
      --disable-password) DISABLE_PASSWORD="yes" ;;
      --disable-22) DISABLE_22="yes" ;;
      --keep-allowusers) KEEP_ALLOWUSERS="yes" ;; # will be ignored
    esac
  done

  cancel_rollback_fuse

  [[ -s "$USER_FILE" ]] || { echo "没有找到上次运行的状态文件：$USER_FILE"; exit 1; }
  LOGIN_USER="$(cat "$USER_FILE")"
  valid_username_or_exit "$LOGIN_USER"

  ensure_sshd_include_dir
  neutralize_cloudimg_passwordauth

  # --- 强制收紧（忽略 keep-allowusers）---
  if [[ "$KEEP_ALLOWUSERS" == "yes" ]]; then
    echo "[WARN] confirm 阶段将忽略 --keep-allowusers（避免把 root/ubuntu 等重新放回 AllowUsers），将强制收紧为：${LOGIN_USER}"
    logi "WARN" "ignored --keep-allowusers in confirm; forced tighten to ${LOGIN_USER}"
  fi
  allow_users_final="${LOGIN_USER}"
  echo "[CONFIRM] 收紧 AllowUsers -> 仅允许：${allow_users_final}"

  # 同步 harden + 主配置（避免 AllowUsers 叠加导致 root/ubuntu 还有效）
  confirm_edit_allowusers "$allow_users_final"
  confirm_sync_main_allowusers "$allow_users_final"

  if [[ "$DISABLE_PASSWORD" == "yes" ]]; then
    keys_enabled="no"
    [[ -f "$KEYS_ENABLED_FILE" ]] && keys_enabled="$(cat "$KEYS_ENABLED_FILE" || echo no)"
    if [[ "$keys_enabled" != "yes" ]]; then
      echo "错误：你要求 --disable-password，但上次运行时未启用公钥登录（为避免锁门，拒绝执行）。"
      exit 1
    fi
    user_home="$(eval echo "~${LOGIN_USER}")"
    auth_keys="${user_home}/.ssh/authorized_keys"
    if [[ ! -s "$auth_keys" ]]; then
      echo "错误：检测到 ${auth_keys} 为空或不存在，无法安全关闭密码登录。"
      exit 1
    fi
    echo "[CONFIRM] 关闭密码登录，仅保留公钥登录。"
    confirm_disable_password_only
  fi

  if [[ "$DISABLE_22" == "yes" ]]; then
    confirm_disable_22
  fi

  sshd -t
  svc_reload_ssh

  echo "[CONFIRM] 完成。"
  exit 0
fi

if [[ "${1:-}" == "--rollback" ]]; then
  do_rollback_now
  exit 0
fi

# ---------------- main ----------------
echo "============================================"
echo "   Linux 服务器更稳加固脚本（上传公钥版）"
echo " (Create User + SSH Port + UFW + Fail2Ban)"
echo " + systemd 保险丝 + 回滚日志 + 一键回滚"
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

read -rp "是否启用公钥登录？(建议 yes) [yes/no]: " ENABLE_KEYS
ENABLE_KEYS="${ENABLE_KEYS:-yes}"

echo "$LOGIN_USER" > "$USER_FILE"
echo "$SSH_PORT" > "$SSH_PORT_FILE"
echo "${EXTRA_PORTS:-}" > "$EXTRA_PORTS_FILE"
echo "$KEEP_PORT22" > "$KEEP22_FILE"
echo "$ENABLE_KEYS" > "$KEYS_ENABLED_FILE"

logi "INFO" "run start user=$LOGIN_USER port=$SSH_PORT keep22=$KEEP_PORT22 extra_ports='${EXTRA_PORTS:-}' enable_keys=$ENABLE_KEYS"

echo
echo "开始处理..."
echo "（提示：脚本将先设置 10 分钟 systemd 自动回滚保险丝，避免锁门）"
set_rollback_fuse 600

echo "[0/6] 确保 sshd_config.d 生效..."
ensure_sshd_include_dir

echo "[0.5/6] 处理 cloudimg 默认配置冲突（如有）..."
neutralize_cloudimg_passwordauth

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

grant_sudo_privilege "${LOGIN_USER}"

: > "$KEYS_FILE" || true

if [[ "$ENABLE_KEYS" == "yes" ]]; then
  tmp_keys="$(mktemp)"
  if read_ssh_keys_multiline "$tmp_keys"; then
    cp -a "$tmp_keys" "$KEYS_FILE"
    install_authorized_keys "$LOGIN_USER" "$tmp_keys"
  else
    echo "错误：你选择启用公钥登录，但没有输入任何公钥。"
    echo "为避免你锁门，当前会继续走“仅密码”策略。"
    echo "no" > "$KEYS_ENABLED_FILE"
    logi "WARN" "enable_keys requested but no keys provided; fallback to password only"
  fi
  rm -f "$tmp_keys"
fi

echo "[2/6] 写入 SSH 加固配置..."
MERGED_ALLOW_USERS="$(compute_allowusers_merge "$LOGIN_USER")"

if [[ "$(cat "$KEYS_ENABLED_FILE")" == "yes" ]]; then
  apply_harden_file "$SSH_PORT" "$MERGED_ALLOW_USERS" "yes" "yes" "yes"
else
  apply_harden_file "$SSH_PORT" "$MERGED_ALLOW_USERS" "yes" "no" "yes"
fi

echo "检查 sshd 配置语法..."
sshd -t

echo "[3/6] 安装并配置 UFW 防火墙..."
apt-get update -y
apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow "${SSH_PORT}/tcp" comment "SSH new port"
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
logi "INFO" "fail2ban configured for sshd port=$SSH_PORT"

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
echo "登录方式: 密码 + $([[ "$(cat "$KEYS_ENABLED_FILE")" == "yes" ]] && echo '公钥(已启用)' || echo '公钥(未启用)')"
echo "AllowUsers(当前合并模式): ${MERGED_ALLOW_USERS}"
echo "额外放行端口: ${EXTRA_PORTS:-无}"
echo "UFW 放行 22: $([[ "${KEEP_PORT22}" == "yes" ]] && echo '暂时保留(建议验证后关闭)' || echo '未放行')"
echo
echo "重要：当前已设置 10 分钟 systemd 自动回滚保险丝。"
echo "请立刻新开终端测试："
echo "  - ssh -p ${SSH_PORT} ${LOGIN_USER}@<服务器IP>"
echo
echo "确认一切正常后执行（会强制收紧 AllowUsers 为单用户）："
echo "  - 收紧 AllowUsers：sudo ./${SCRIPT_NAME} --confirm"
echo "  - 收紧 AllowUsers 且关闭密码（只留公钥）：sudo ./${SCRIPT_NAME} --confirm --disable-password"
echo "  - 收紧 AllowUsers 并关闭 22（删UFW放行 + sshd不再监听22）：sudo ./${SCRIPT_NAME} --confirm --disable-22"
echo
echo "如需查看回滚/确认日志：sudo tail -n 50 ${ROLLBACK_LOG}"
echo "如果出现问题，可直接执行：sudo ./${SCRIPT_NAME} --rollback （一键回滚）"
echo "============================================"
