
# vps-hardening

Ubuntu/Debian VPS 一键加固脚本（systemd），主要用于 SSH + 防火墙 + Fail2Ban 的基础安全加固，带“自动回滚保险丝”避免锁门。

---

## 功能概览

- 创建/确认普通登录用户（非 root）
- 赋予该用户 sudo（需要密码，不是免密）
- 修改 SSH 端口（新端口可选）
- 禁止 root 直接 SSH 登录（PermitRootLogin no）
- 仅允许指定用户登录（AllowUsers）
- 登录方式：
  - 默认：**密码开启**（救援用，防止误锁）
  - 可选：**启用公钥登录**（交互粘贴公钥写入 authorized_keys）
  - 可选：确认无误后 **关闭密码仅保留公钥**（`--confirm --disable-password`）
- UFW 防火墙：
  - 默认拒绝入站、允许出站
  - 放行：SSH 新端口
  - 可选：临时保留 22（建议先保留，验证后再关）
  - 可选：额外业务端口（逗号分隔）
- Fail2Ban：
  - 保护 SSH（按新端口监控）
  - 自动封禁爆破/异常尝试 IP（可能会误封自己）
- 自动回滚保险丝（默认 10 分钟）
- 一键回滚（撤销脚本主要改动）

> 建议：最终形态优先用“公钥登录 + 关闭密码 + 关闭 22 +（可选）限制来源 IP/安全组”。

---

## 适用系统

- Ubuntu / Debian
- systemd 环境

---

## 快速开始

### 方式 A：下载后执行（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/MuXiQingLang/vps-hardening/main/secure_setup_password.sh -o secure_setup_password.sh
chmod +x secure_setup_password.sh
sudo ./secure_setup_password.sh
````

脚本会交互询问：

1. 登录用户名（建议非 root）
2. SSH 新端口（建议 10000–65535）
3. 是否保留 22（建议先 yes，确认后再关）
4. 额外放行 TCP 端口（例如 `80,443,2334`）
5. 是否启用公钥登录（建议 yes；随后粘贴公钥，多行可用，输入 `END` 结束）

---

## 非常重要：避免锁门流程

脚本默认开启 **10 分钟自动回滚保险丝**。你必须在**新终端**验证登录正常后，再取消保险丝。

### 1）新终端测试 SSH（推荐至少测一次密码/一次公钥）

```bash
ssh -p <NEW_PORT> <USER>@<SERVER_IP>
```

如果你想明确指定只走某一种认证方式（可选）：

* 仅密码：

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -p <NEW_PORT> <USER>@<SERVER_IP>
```

* 仅公钥：

```bash
ssh -o PreferredAuthentications=publickey -p <NEW_PORT> <USER>@<SERVER_IP>
```

### 2）确认无误后，取消保险丝 + 收紧 AllowUsers

默认确认会把 AllowUsers 收紧为“只允许你创建/指定的用户”。

```bash
sudo ./secure_setup_password.sh --confirm
```

如果你不想收紧（保留合并模式）：

```bash
sudo ./secure_setup_password.sh --confirm --keep-allowusers
```

### 3）确认公钥可用后，关闭密码（更安全）

```bash
sudo ./secure_setup_password.sh --confirm --disable-password
```

脚本会在关闭密码前检查 `~<USER>/.ssh/authorized_keys` 是否存在且非空，避免误锁。

### 4）验证新端口稳定后，再关闭 22（建议）

默认 `--confirm` **不会**关闭 22。要关 22 用：

```bash
sudo ./secure_setup_password.sh --confirm --disable-22
```

它会尝试：

* 从 UFW 删除 22 放行
* 注释主配置里的 `Port 22`（让 sshd 不再监听 22）

> 关闭 22 前请确保：你已经能稳定用新端口登录，并且云厂商安全组/防火墙也允许新端口。

---

## 一键回滚

### 立即回滚（SSH/UFW/Fail2Ban）

```bash
sudo ./secure_setup_password.sh --rollback
```

回滚会做的事（best-effort）：

* 禁用 `/etc/ssh/sshd_config.d/99-hardening.conf`（搬到 `/root` 留档）
* 尝试还原/放开防火墙（优先 iptables 备份，否则 `ufw disable`）
* 重启 SSH
* 停止 Fail2Ban（避免误封）

---

## 查看状态/排错常用命令

### 看 sshd 最终生效配置（强烈推荐用它判断“到底生效了啥”）

```bash
sudo sshd -T | egrep -i '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|allowusers)\b'
```

### 看监听端口

```bash
sudo ss -lntp | grep sshd
```

### 看 UFW 放行

```bash
sudo ufw status verbose
sudo ufw status numbered
```

### 看 Fail2Ban 是否封了谁（以及解封）

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip <YOUR_IP>
```

> 如果你在本机看到 `Connection closed by ...`，而服务器侧日志没进入到密码提示阶段，很可能是：
>
> * 你的 IP 被 Fail2Ban 封了
> * 云安全组/外部防火墙没放行新端口
> * sshd 实际没在新端口监听（配置没加载/被回滚/服务未重启）

---

## 关于“额外端口放行”的提醒

如果你有网站/反代（Nginx/Caddy/Apache），通常需要：`80,443`。
如果你运行其他对外服务（示例：Xray、面板、应用端口），把对应端口加到“额外放行端口”。

建议：仅给反代使用的后端服务只监听 `127.0.0.1`，不要直接对公网开放。

---

## 安全建议（可选增强）

* 最终使用：公钥登录 + 关闭密码 + 关闭 22
* 配合云厂商安全组：仅允许你的管理 IP 访问 SSH 端口
* 如果你经常换网（IP 变动大），可以先别做“只允许单 IP”，避免误锁

```
