# Emergency Response & Malware Hunting Toolkit

一套面向实战应急响应场景的 **Linux 应急处置与恶意程序定位工具套件**，强调：
基于https://github.com/vuln000/BlueTeamNote 笔记的经验，进行了一定的优化与完善。

目前仅完成了Linux版本：[`linux_check.sh`]
Windows版本下工具较多，暂缓。
---

## 功能概览

### Phase 1：主机基础信息搜集（留档 + 日志打包）
- **发行版信息**：`lsb_release -a`（如不可用则兜底读取 `/etc/*release`）
- **内核/运行状态**：`uname`、`uptime`
- **登录溯源**：`last -n 10`
- **网络连接快照**：`ss -tunpa`（剔除回环地址），保留所有连接状态
- **进程资源消耗 Top**：CPU/内存视角快速定位挖矿/异常进程
- **留档**：
  - 生成 `phase1_recon_YYYYmmdd_HHMMSS.txt`（已去除 ANSI 颜色控制符，适合归档/报告）
  - 打包 `/var/log` 为 `var_log_backup_YYYYmmdd_HHMMSS.tar.gz`

### Phase 2：恶意程序定位引擎
- **Module 1：时间线落地排查**
  - 支持按 `ctime/mtime/atime` 三种时间戳选择
  - 支持输入需跳过扫描的目录列表（逗号分隔）
  - 目标：定位特定时间窗内落地/变化的 ELF 可执行文件
- **Module 1.5：进程启动时间统计**
  - 按天统计“当前存活进程”的启动数量，并按数量倒序输出
- **Module 2：网络 IOC 定位进程（含 Anti-Rootkit 思路）**
  - 常规层：`ss -tunpa` 快速抓取目标 IP 的连接
  - 深度层：解析 `/proc/net/tcp` / `/proc/net/udp` 的 inode，再遍历 `/proc/[pid]/fd` 反查 PID
- **Module 3：内存特征字符串定位**
  - 遍历 `/proc/[pid]/maps` + `dd` 读取 `/proc/[pid]/mem`
  - 命中后打印：PID、exe、cmdline，并输出 **命中字符串上下文片段**

### Phase 3：追踪恶意启动项（持久化机制暴搜）
- 对 `/etc`、`/var/spool/cron`、`/usr/lib/systemd`、`/opt`、`/root` 等目录进行关键字检索
- 排除 `/var/log`、`/proc`、`/sys` 等海量或虚拟目录提升速度

### Phase 4：样本静态辅助研判（不执行样本）
- `file` 识别真实类型（防双扩展伪装）
- `md5sum` / `sha256sum` 输出哈希（便于威胁情报查询）
- `strings` + 高危关键词/协议/壳特征过滤（如 `UPX!`、`stratum+tcp`、`bind/listen`、`aes/rsa/encrypt` 等）

---

## 使用方法

### 1）获取脚本

```bash
git clone <your_repo_url>
cd <repo_dir>
chmod +x linux_check.sh
```

### 2）以 root 运行

脚本需要访问 `/proc/[pid]/mem`、`/proc/net/*` 等信息，建议直接 root 执行：

```bash
sudo -i
./linux_check.sh
```

### 3）交互式菜单

按提示输入序号进入对应阶段/模块。部分模块会要求输入：
- 时间窗（START / END）
- 目标 IP（Network IOC）
- 特征字符串（Memory String）
- 样本路径（Quick Static Triage）

---

## 输出与留档

### Phase 1 输出文件（当前目录）
- `phase1_recon_YYYYmmdd_HHMMSS.txt`：Phase 1 全部输出的文本留档（已去色）
- `var_log_backup_YYYYmmdd_HHMMSS.tar.gz`：`/var/log` 打包备份

---

## 调试模式（命令回显）

脚本会在每个关键动作后输出类似以下内容：

```text
[Debug CMD] <刚刚执行的命令>
```

便于你在现场直接复制命令进行二次过滤、扩大范围或快速复现。

---

## 依赖与兼容性

### 依赖命令（大多为系统自带）
- bash, awk, grep, ps, ss, find, dd, strings, tar, stat, md5sum, sha256sum, file

### 可选命令
- `lsb_release`：若缺失会自动兜底读取 `/etc/*release`

---

## 安全声明

- 本项目面向 **授权的应急响应/攻防演练** 场景，使用者需确保符合组织合规要求与法律法规。
- 工具默认以只读采集为主，但 **Phase 1 会对 `/var/log` 进行打包并在当前目录落地压缩包**，请在取证流程中妥善管理该文件的权限与传输链路。

---

## License

建议将本项目以 MIT License 发布（如需我补充 LICENSE 文件可以继续说一声）。

