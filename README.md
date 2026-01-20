# vps-hardening

Ubuntu/Debian VPS 一键加固脚本（systemd），主要用于 SSH + 防火墙 + Fail2Ban 的基础安全加固。

包含功能：

- 创建/确认普通登录用户（非 root）
- 修改 SSH 端口
- 禁止 root 直接 SSH 登录
- 仅允许指定用户登录（AllowUsers）
- **密码登录模式**（禁用公钥登录）
- UFW 防火墙：默认拒绝入站，仅放行 SSH 新端口 + 可选保留 22 + 可选额外业务端口
- Fail2Ban：保护 SSH（按新端口监控）
- 自动回滚保险丝（默认 10 分钟）
- 一键回滚（撤销脚本主要改动）

> 注意：纯密码 SSH 的抗爆破能力弱于密钥方式。强烈建议配合强密码、限制来源 IP、云厂商安全组策略使用。

---

## 适用系统

- Ubuntu / Debian
- systemd 环境

---

## 快速开始

### 方式 A：下载后执行（推荐）

> 先下载到服务器，最好看一眼脚本内容，再运行。

```bash
curl -fsSL https://raw.githubusercontent.com/MuXiQingLang/vps-hardening/main/secure_setup_password.sh -o secure_setup_password.sh
chmod +x secure_setup_password.sh
sudo ./secure_setup_password.sh
````

脚本执行完后，请在**新终端**测试 SSH：

```bash
ssh -p <NEW_PORT> <USER>@<SERVER_IP>
```

确认一切正常后，取消自动回滚保险丝（很重要）：

```bash
sudo ./secure_setup_password.sh --confirm
```

如出现问题，需要立刻回滚：

```bash
sudo ./secure_setup_password.sh --rollback
```

---

### 方式 B：一行命令直接跑（不推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/MuXiQingLang/vps-hardening/main/secure_setup_password.sh | sudo bash
```

不推荐原因：不落地查看脚本内容，风险更高。更稳的做法是固定到某个 commit SHA 再运行。

---

## 交互式输入说明

运行脚本后会询问：

1. 登录用户名：脚本会创建该用户或复用已有用户
2. SSH 新端口：建议 10000–65535
3. 是否保留 22：建议先保留，确认新端口可登录后再关闭
4. 额外放行端口：逗号分隔，例如：`80,443,2334,8080`

> 提醒：你服务器如果已经有业务端口（例如你之前 `ss` 里看到的 `xray` 监听 `2334/tcp`），一定要把对应端口加入“额外放行端口”，否则启用 UFW 后业务可能被拦截。

---

## 重要：避免把自己锁在门外

* **不要关闭当前 SSH 会话**
* 脚本默认开启 **10 分钟自动回滚保险丝**
* 你必须在新终端确认 `ssh -p 新端口 用户@IP` 可登录后，再执行：

```bash
sudo ./secure_setup_password.sh --confirm
```

否则到时间会自动回滚（恢复到更容易连上的状态）。

---

## 防火墙端口放行建议

如果你有网站/反代（Nginx/Caddy/Apache）：

* 通常需要：`80,443`

如果你运行了其他对外服务（示例）：

* Xray：例如 `2334`
* 自定义应用：例如 `8080`

> 仅给反代使用的后端服务建议只监听 `127.0.0.1`，不对公网开放端口。

---

## 查看当前端口占用

在服务器执行：

```bash
sudo ss -lntup
```

如果使用 Docker：

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
```

---

## 回滚说明

### 取消保险丝（确认系统一切正常后执行）

```bash
sudo ./secure_setup_password.sh --confirm
```

### 一键回滚（SSH/UFW/Fail2Ban）

```bash
sudo ./secure_setup_password.sh --rollback
```

回滚会做的事（best-effort）：

* 禁用 `/etc/ssh/sshd_config.d/99-hardening.conf`
* 尝试还原/放开防火墙（优先还原 iptables 备份，否则 `ufw disable`）
* 重启 SSH 服务
* 停止 Fail2Ban（避免误封）

