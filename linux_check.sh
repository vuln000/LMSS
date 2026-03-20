#!/usr/bin/env bash
# ==============================================================================
# Linux Emergency Response & Malware Hunting Toolkit
# Linux 应急处置与恶意程序定位工具套件 (纯 Bash 高可用版)
# ==============================================================================
# 设计原则:
# 1. 只读安全：不对系统文件和恶意样本做任何写操作，保护电子证据现场。
# 2. 纯原生命令：依赖 find, grep, awk, ss, ps, dd, strings 等原生命令。
# 3. 容错防阻塞：大量使用 2>/dev/null，防止遇到无权限或被锁定的文件时卡死。
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

check_env() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] 致命错误: 必须以 root 权限运行此脚本！${NC}"
        exit 1
    fi
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
}

# ==============================================================================
# Phase 1: 主机基础信息搜集 (Host Recon)
# ==============================================================================
phase1_host_recon() {
    clear
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local OUTPUT_TXT="phase1_recon_${TIMESTAMP}.txt"
    local LOG_BACKUP="var_log_backup_${TIMESTAMP}.tar.gz"

    echo -e "${CYAN}==============================================================${NC}"
    echo -e "${CYAN}           Phase 1: 主机基础信息搜集 (Host Recon)             ${NC}"
    echo -e "${CYAN}==============================================================${NC}"
    echo -e "${YELLOW}[*] 正在搜集信息，结果将保存至当前目录的 ${OUTPUT_TXT}${NC}"
    echo -e "${YELLOW}[*] 正在打包 /var/log 日志，将保存至 ${LOG_BACKUP}${NC}"

    # 搜集信息并同时输出到屏幕和TXT文件 (通过 sed 过滤掉颜色控制符)
    {
        echo -e "\n${GREEN}[+] 1.1 基础运行状态 (发行版、内核、登录记录)${NC}"
        echo -e "${YELLOW}--- 系统发行版信息 ---${NC}"
        local CMD_LSB="lsb_release -a 2>/dev/null || cat /etc/*release 2>/dev/null"
        eval "$CMD_LSB"
        echo -e "${BLUE}[Debug CMD] $CMD_LSB${NC}"
        
        echo -e "\n${YELLOW}--- 内核信息 ---${NC}"
        local CMD_UNAME="uname -snrvm"
        eval "$CMD_UNAME"
        echo -e "${BLUE}[Debug CMD] $CMD_UNAME${NC}"
        
        echo -e "\n${YELLOW}--- 运行时间与系统负载 ---${NC}"
        local CMD_UPTIME="uptime"
        eval "$CMD_UPTIME"
        echo -e "${BLUE}[Debug CMD] $CMD_UPTIME${NC}"
        
        echo -e "\n${YELLOW}--- 最近登录用户 (Top 10) ---${NC}"
        local CMD_LAST="last -n 10 2>/dev/null | grep -v '^$'"
        eval "$CMD_LAST"
        echo -e "${BLUE}[Debug CMD] $CMD_LAST${NC}"

        echo -e "\n${GREEN}[+] 1.2 所有网络连接状态 (剔除本地回环)${NC}"
        # 提取所有网络状态，不仅仅是 ESTABLISHED，保留 header
        local CMD_SS="ss -tunpa 2>/dev/null | awk 'NR==1 {print \$0} NR>1 && \$5 !~ /127\.0\.0\.1|::1/ {print \$0}' | column -t"
        eval "$CMD_SS"
        echo -e "${BLUE}[Debug CMD] $CMD_SS${NC}"

        echo -e "\n${GREEN}[+] 1.3 资源消耗异常进程状态 (Top 10)${NC}"
        local CMD_PS="ps -eo pid,user,%cpu,%mem,lstart,cmd --sort=-%cpu 2>/dev/null | head -n 11"
        eval "$CMD_PS"
        echo -e "${BLUE}[Debug CMD] $CMD_PS${NC}"
        
    } | tee >(sed "s/$(printf '\033')\[[0-9;]*[mK]//g" > "$OUTPUT_TXT")

    # 打包 /var/log 日志备份
    echo -e "\n${GREEN}[+] 1.4 正在打包 /var/log 系统日志目录...${NC}"
    local CMD_TAR="tar -czf \"$LOG_BACKUP\" /var/log 2>/dev/null"
    eval "$CMD_TAR"
    echo -e "${BLUE}[Debug CMD] $CMD_TAR${NC}"
    
    if [ -f "$LOG_BACKUP" ]; then
        echo -e "${GREEN}[+] 日志打包完成: ${LOG_BACKUP}${NC}"
    else
        echo -e "${RED}[!] 日志打包失败，请检查权限。${NC}"
    fi

    echo -e "\n${GREEN}[+] Phase 1 基础搜集完毕。报告已保存为: ${OUTPUT_TXT}${NC}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ==============================================================================
# Phase 2: 恶意程序定位引擎 (Malware Hunting Engine)
# ==============================================================================

# ------------------------------------------------------------------------------
# Module 1: 基于时间信息定位恶意程序 (Time-based Hunting)
# ------------------------------------------------------------------------------
module1_time_based_hunting() {
    clear
    echo -e "${CYAN}=== Module 1: 基于时间信息定位恶意文件 ===${NC}"
    echo -e "${YELLOW}实战场景: 已知告警发生时间，排查该时间段内落地的 ELF 可执行文件。${NC}"
    
    read -p "请输入起始时间 (格式如 '2023-10-01 12:00:00' 或 '1 days ago'): " START_TIME
    read -p "请输入结束时间 (格式如 '2023-10-02 12:00:00' 或 'now'): " END_TIME

    if [[ -z "$START_TIME" || -z "$END_TIME" ]]; then
        echo -e "${RED}[!] 时间不能为空。${NC}"
        read -n 1 -s -r -p "按任意键返回主菜单..."
        return
    fi

    echo -e "${YELLOW}提示: 默认已排除跨挂载点，防止扫描网络存储导致卡死。${NC}"
    read -p "请输入需要额外跳过的目录 (多个目录用逗号分隔，如 /var/log,/tmp)，直接回车表示不跳过: " SKIP_DIRS

    echo -e "\n${YELLOW}请选择要基于哪种时间戳进行排查：${NC}"
    echo -e "  [1] ctime (状态改变时间 - 推荐，难以伪造)"
    echo -e "  [2] mtime (内容修改时间)"
    echo -e "  [3] atime (访问时间)"
    read -p "请输入选项 [1-3] (默认1): " TIME_TYPE_CHOICE

    local TIME_FLAG="c"
    local TIME_DESC="状态改变(ctime)"
    case "$TIME_TYPE_CHOICE" in
        2) TIME_FLAG="m"; TIME_DESC="内容修改(mtime)" ;;
        3) TIME_FLAG="a"; TIME_DESC="访问(atime)" ;;
        *) TIME_FLAG="c"; TIME_DESC="状态改变(ctime)" ;;
    esac

    # 动态构建 find 的排除目录参数
    # 正确的 find 语法应该是: find / \( -path "/dir1" -o -path "/dir2" \) -prune -o -type f ... -print
    EXCLUDE_PARAMS=""
    if [[ -n "$SKIP_DIRS" ]]; then
        IFS=',' read -ra DIRS <<< "$SKIP_DIRS"
        local path_exprs=""
        for dir in "${DIRS[@]}"; do
            # 移除结尾可能的斜杠，以防用户输入 /var/log/
            dir="${dir%/}"
            if [[ -n "$dir" ]]; then
                if [[ -z "$path_exprs" ]]; then
                    path_exprs="-path \"$dir\""
                else
                    path_exprs="$path_exprs -o -path \"$dir\""
                fi
            fi
        done
        if [[ -n "$path_exprs" ]]; then
            EXCLUDE_PARAMS="\\( $path_exprs \\) -prune -o"
        fi
        echo -e "${CYAN}[*] 已配置跳过目录: ${SKIP_DIRS}${NC}"
    fi

    echo -e "\n${GREEN}[+] 1. 排查指定时间段内 ${TIME_DESC} 的 ELF 可执行文件...${NC}"
    echo -e "${YELLOW}(此过程可能需要几十秒，请耐心等待...)${NC}"
    
    # 构造并执行最终的 find 命令
    # 注意末尾添加了 -print，否则带有 -prune -o 的表达式可能不会打印出预期的结果
    local FIND_CMD="find / -mount ${EXCLUDE_PARAMS} -type f -executable -newer${TIME_FLAG}t \"$START_TIME\" ! -newer${TIME_FLAG}t \"$END_TIME\" -print 2>/dev/null"
    


    eval "$FIND_CMD" | while read -r filepath; do
        if file "$filepath" 2>/dev/null | grep -q "ELF"; then
            echo -e "${RED}[!] 发现可疑文件落地: $filepath${NC}"
            stat "$filepath" | grep -E "Modify|Change"
            md5sum "$filepath" 2>/dev/null
            echo "----------------------------------------"
        fi
    done

    echo -e "\n${GREEN}[+] 落地文件排查完毕。${NC}"
    # 打印出构建的命令方便调试
    echo -e "${BLUE}[Debug] FIND_CMD: $FIND_CMD${NC}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ------------------------------------------------------------------------------
# Module 1.5: 基于时间信息定位异常进程 (Process Time Hunting)
# ------------------------------------------------------------------------------
module1_5_process_time_hunting() {
    clear
    echo -e "${CYAN}=== Module 1.5: 基于启动时间排查异常进程 ===${NC}"
    echo -e "${YELLOW}实战场景: 针对持久化运行的后门或挖矿木马，通过精确的启动时间来辅助筛选。${NC}"
    
    echo -e "\n${GREEN}[+] 1. 所有存活进程按启动时间排序 (最新启动的在最后)...${NC}"
    echo -e "${YELLOW}(提示: lstart 字段无法被常规手段轻易篡改，可信度较高)${NC}"
    
    # 获取进程列表并存入临时变量，避免多次执行 ps 导致数据不一致
    local CMD_PS="ps -eo pid,user,lstart,cmd --sort=lstart 2>/dev/null | grep -v 'grep'"
    local PS_OUTPUT=$(eval "$CMD_PS")
    
    # 打印原始进程列表（限制输出前 3 条和后 3 条，避免刷屏，或者用户自行翻页）
    echo "$PS_OUTPUT" | head -n 3
    echo -e "${YELLOW}... (中间输出已省略) ...${NC}"
    echo "$PS_OUTPUT" | tail -n 3
    echo -e "${BLUE}[Debug CMD] $CMD_PS${NC}"
    
    echo -e "\n${GREEN}[+] 2. 存活进程按天启动数量统计 (倒序排列)...${NC}"
    echo -e "${YELLOW}日期格式: 月份 日期 年份 | 启动进程数量${NC}"
    
    # lstart 输出格式通常为: Fri Oct 27 10:00:00 2023
    # 提取按天日期并统计数量，最后按数量倒序排列
    local CMD_AWK="echo \"\$PS_OUTPUT\" | awk 'NR>1 { for(i=1;i<=NF;i++) { if (\$i ~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}$/) { print \$(i-2), \$(i-1), \$(i+1); break; } } }' | sort | uniq -c | sort -nr"
    eval "$CMD_AWK" | while read count month day year; do
        echo -e "  -> ${CYAN}${month} ${day} ${year}${NC} : 共启动了 ${RED}${count}${NC} 个存活进程"
    done
    echo -e "${BLUE}[Debug CMD] ps ... | awk '...' | sort | uniq -c | sort -nr${NC}"

    echo -e "\n${YELLOW}提示: 如果某一天进程数量异常，可使用以下命令手动查看详情：${NC}"
    echo -e "  ps -eo pid,user,lstart,cmd | grep -i 'Oct 27' | less"
    
    echo -e "\n${GREEN}[+] 进程启动时间排查完毕。${NC}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ------------------------------------------------------------------------------
# Module 2: 基于网络活动 IOC 定位进程 (Network IOC Hunting)
# ------------------------------------------------------------------------------
module2_network_ioc_hunting() {
    clear
    echo -e "${CYAN}=== Module 2: 基于网络活动 IOC 定位进程 ===${NC}"
    echo -e "${YELLOW}实战场景: 威胁情报提示主机在连接恶意 IP，需绕过 Rootkit 隐藏揪出真实 PID。${NC}"
    
    read -p "请输入要追踪的恶意目标 IP (如 8.8.8.8): " TARGET_IP
    if [[ -z "$TARGET_IP" ]]; then return; fi

    echo -e "\n${GREEN}[+] 阶段一：瞬时连接捕获 (常规层 ss/netstat 捕获)${NC}"
    local CMD_SS="ss -tunpa 2>/dev/null | grep --color=always \"$TARGET_IP\""
    eval "$CMD_SS"
    echo -e "${BLUE}[Debug CMD] $CMD_SS${NC}"

    echo -e "\n${GREEN}[+] 阶段二：Anti-Rootkit 深度底层 Socket 追溯${NC}"
    echo -e "${YELLOW}[*] 原理: 将 IP 转换为 16 进制小端序，直接读取 /proc/net/tcp 获取 inode，并遍历 /proc/[pid]/fd${NC}"
    
    # 将 IP 转换为 /proc/net/tcp 中的小端序 16 进制格式 (例如 192.168.1.5 -> 0501A8C0)
    IFS='.' read -r i1 i2 i3 i4 <<< "$TARGET_IP"
    HEX_IP=$(printf "%02X%02X%02X%02X" "$i4" "$i3" "$i2" "$i1")
    echo -e "[-] 目标 IP $TARGET_IP 的小端序 Hex 为: ${CYAN}$HEX_IP${NC}"

    # 从 /proc/net/tcp 提取 inode (第10列)
    local CMD_INODES="cat /proc/net/tcp /proc/net/udp 2>/dev/null | grep -i \"$HEX_IP\" | awk '{print \$10}'"
    TARGET_INODES=$(eval "$CMD_INODES")
    echo -e "${BLUE}[Debug CMD] $CMD_INODES${NC}"
    
    if [[ -z "$TARGET_INODES" ]]; then
        echo -e "${GREEN}[-] 当前 /proc/net 层未发现与该 IP 建立的 Socket 连接。${NC}"
    else
        for inode in $TARGET_INODES; do
            echo -e "${RED}[!] 发现隐蔽 Socket Inode: $inode，正在反查关联 PID...${NC}"
            # 暴力遍历所有进程的文件描述符，寻找持有该 inode 的进程
            local CMD_FIND_FD="find /proc/[0-9]*/fd -lname \"socket:\\[$inode\\]\" 2>/dev/null"
            echo -e "${BLUE}[Debug CMD] $CMD_FIND_FD${NC}"
            eval "$CMD_FIND_FD" | while read -r fd_path; do
                PID=$(echo "$fd_path" | cut -d '/' -f 3)
                echo -e "${RED}[!] 成功定位隐藏恶意进程 PID: $PID${NC}"
                
                local CMD_READLINK="readlink /proc/$PID/exe 2>/dev/null"
                echo -e "${YELLOW}  -> 进程执行路径: $(eval "$CMD_READLINK")${NC}"
                echo -e "     ${BLUE}[Debug CMD] $CMD_READLINK${NC}"
                
                local CMD_CMDLINE="cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' '"
                echo -e "${YELLOW}  -> 进程启动命令: $(eval "$CMD_CMDLINE")${NC}"
                echo -e "     ${BLUE}[Debug CMD] $CMD_CMDLINE${NC}"
            done
        done
    fi

    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ------------------------------------------------------------------------------
# Module 3: 基于内存特征字符串定位 (Memory String Hunting)
# ------------------------------------------------------------------------------
module3_memory_string_hunting() {
    clear
    echo -e "${CYAN}=== Module 3: 基于内存特征字符串定位 ===${NC}"
    echo -e "${YELLOW}实战场景: 针对无文件内存马或变种矿机，直接在内存中暴搜 C2 域名或矿池地址。${NC}"
    
    read -p "请输入要暴搜的内存特征字符串 (如 evil.com): " TARGET_STR
    if [[ -z "$TARGET_STR" ]]; then return; fi

    echo -e "\n${GREEN}[+] 正在安全遍历系统所有进程内存 (利用 dd 和 maps 映射提取)...${NC}"
    echo -e "${YELLOW}[*] 提示: 此过程需逐个转储进程内存，可能较慢，但绝对安全不会引发 Kernel Panic。${NC}"

    # 遍历所有纯数字的 PID 目录
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        # 1. 快速排查层: cmdline 和 environ (速度极快)
        local CMD_GREP_ENV="grep -q -a \"$TARGET_STR\" /proc/$pid/cmdline /proc/$pid/environ 2>/dev/null"
        if eval "$CMD_GREP_ENV"; then
             echo -e "${RED}[!] 内存浅层(cmdline/environ)匹配命中! PID: $pid${NC}"
             
             local CMD_CMDLINE="cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '"
             echo -e "  -> 命令行: $(eval "$CMD_CMDLINE")"
             echo -e "     ${BLUE}[Debug CMD] $CMD_CMDLINE${NC}"
             
             echo -e "  -> 上下文片段:"
             # 提取匹配处的上下文
             local CMD_ENV_CONTEXT="cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -C 2 -a --color=always \"$TARGET_STR\" | sed 's/^/       /'"
             eval "$CMD_ENV_CONTEXT"
             echo -e "     ${BLUE}[Debug CMD] cat /proc/$pid/environ ... | grep -C 2 -a \"$TARGET_STR\"${NC}"
             continue
        fi

        # 2. 深度排查层: /proc/$pid/mem
        if [ -r /proc/$pid/maps ] && [ -r /proc/$pid/mem ]; then
            # 筛选具有读取权限(r)的内存段
            local CMD_MAPS="grep -E \"^[0-9a-f]+-[0-9a-f]+ r\" /proc/$pid/maps 2>/dev/null"
            eval "$CMD_MAPS" | while read -r line; do
                mem_range=$(echo "$line" | awk '{print $1}')
                start_hex=${mem_range%-*}
                end_hex=${mem_range#*-}
                
                # 转换为十进制
                start_dec=$((16#$start_hex))
                end_dec=$((16#$end_hex))
                size=$((end_dec - start_dec))

                # 为防止 dd 卡死，限制提取的块大小为 4096 (一页)，跳过对应的页数
                skip_blocks=$((start_dec / 4096))
                count_blocks=$((size / 4096))

                # 若内存段小于 4096 或极大(>100MB)，为保证脚本响应速度可酌情跳过，此处设定最大提取 50MB(12800块)
                if [[ $count_blocks -gt 0 && $count_blocks -lt 12800 ]]; then
                    # 核心安全操作：使用 dd 提取，通过 bs=4096 严格对齐内存页，防止 Bad Address 报错中断脚本
                    # 将提取到的内存段内容缓存到临时变量中进行匹配，避免重复读取
                    local CMD_DD="dd if=/proc/$pid/mem bs=4096 skip=$skip_blocks count=$count_blocks 2>/dev/null | strings"
                    local MEM_CHUNK=$(eval "$CMD_DD")
                    
                    if echo "$MEM_CHUNK" | grep -q "$TARGET_STR"; then
                        echo -e "\n${RED}[!] 深度内存特征(mem)命中! PID: $pid${NC}"
                        
                        local CMD_READLINK="readlink /proc/$pid/exe 2>/dev/null"
                        echo -e "  -> 执行路径: $(eval "$CMD_READLINK")"
                        echo -e "     ${BLUE}[Debug CMD] $CMD_READLINK${NC}"
                        
                        local CMD_CMDLINE2="cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '"
                        echo -e "  -> 命令行: $(eval "$CMD_CMDLINE2")"
                        echo -e "     ${BLUE}[Debug CMD] $CMD_CMDLINE2${NC}"
                        
                        echo -e "  -> ${YELLOW}内存上下文片段 (前后 5 行):${NC}"
                        echo -e "     ${BLUE}[Debug CMD] dd if=/proc/$pid/mem bs=4096 skip=$skip_blocks count=$count_blocks ... | strings | grep -C 5 \"$TARGET_STR\"${NC}"
                        
                        # 打印匹配处的上下文信息，高亮目标字符串，缩进排版以便阅读
                        echo "$MEM_CHUNK" | grep -C 5 -a --color=always "$TARGET_STR" | sed 's/^/       /'
                        
                        break # 该进程已确认感染，跳出当前进程的 maps 循环
                    fi
                fi
            done
        fi
    done

    echo -e "\n${GREEN}[+] 内存特征暴搜完毕。${NC}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ==============================================================================
# Phase 3: 追踪恶意程序启动项 (Persistence Tracking)
# ==============================================================================
module4_persistence_tracking() {
    clear
    echo -e "${CYAN}=== Phase 3: 追踪恶意程序启动项 ===${NC}"
    echo -e "${YELLOW}实战场景: 发现恶意文件后，暴搜 /etc, /var 等配置目录，揪出 Crontab、Systemd 等自启驻留点。${NC}"
    
    read -p "请输入已知恶意程序的完整路径或文件名 (如 kdevtmpfsi): " MAL_NAME
    if [[ -z "$MAL_NAME" ]]; then return; fi

    echo -e "\n${GREEN}[+] 正在全量暴搜持久化配置目录...${NC}"
    echo -e "${YELLOW}[*] 原理: grep -rnI 排除了 /var/log 和内核虚拟目录，保证检索速度。${NC}"

    # 核心安全排查：-I 忽略二进制文件，--exclude-dir 排除日志与系统运行时目录，防止搜索爆炸
    local CMD_GREP_PERSIST="grep -rnI --color=always \
        --exclude-dir=\"/var/log\" \
        --exclude-dir=\"/proc\" \
        --exclude-dir=\"/sys\" \
        --exclude-dir=\"/run\" \
        --exclude-dir=\"/dev\" \
        \"$MAL_NAME\" /etc /var/spool/cron /opt /usr/lib/systemd /root 2>/dev/null"
        
    eval "$CMD_GREP_PERSIST"
    echo -e "${BLUE}[Debug CMD] $CMD_GREP_PERSIST${NC}"

    echo -e "\n${GREEN}[+] 持久化特征暴搜完毕。${NC}"
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ==============================================================================
# Phase 4: 可疑样本快速静态辅助判断 (Quick Static Triage)
# ==============================================================================
module5_quick_static_triage() {
    clear
    echo -e "${CYAN}=== Phase 4: 可疑样本快速静态辅助判断 ===${NC}"
    echo -e "${YELLOW}实战场景: 在不运行样本的前提下，提取哈希并过滤高危特征字符串，辅助研判。${NC}"
    
    read -p "请输入可疑文件的完整路径: " FILE_PATH
    if [[ ! -f "$FILE_PATH" ]]; then
        echo -e "${RED}[!] 文件不存在或无权限读取: $FILE_PATH${NC}"
        read -n 1 -s -r -p "按任意键返回主菜单..."
        return
    fi

    echo -e "\n${GREEN}[+] 1. 文件基础画像${NC}"
    local CMD_FILE="file \"$FILE_PATH\""
    eval "$CMD_FILE"
    echo -e "${BLUE}[Debug CMD] $CMD_FILE${NC}"
    
    local CMD_MD5="md5sum \"$FILE_PATH\" 2>/dev/null | awk '{print \$1}'"
    echo -n "MD5:    " && eval "$CMD_MD5"
    echo -e "${BLUE}[Debug CMD] $CMD_MD5${NC}"
    
    local CMD_SHA256="sha256sum \"$FILE_PATH\" 2>/dev/null | awk '{print \$1}'"
    echo -n "SHA256: " && eval "$CMD_SHA256"
    echo -e "${BLUE}[Debug CMD] $CMD_SHA256${NC}"

    echo -e "\n${GREEN}[+] 2. 高危静态特征提取 (IP/域名/系统敏感调用/加壳特征)${NC}"
    # 安全原理：提取可读字符串，并利用正则匹配高危敏感操作
    # 扩展了网络特征、执行调用、隐蔽手法、挖矿与加密勒索相关特征
    local CMD_STRINGS="strings \"$FILE_PATH\" 2>/dev/null | grep -E -i --color=always \
        \"([0-9]{1,3}\\.){3}[0-9]{1,3}|http[s]?://|ftp://|socket|connect|bind|listen|accept|sendto|recvfrom|cmd\\.exe|powershell|/bin/sh|/bin/bash|execve|system|popen|wget|curl|chmod|chown|chattr|UPX!|stratum\\+tcp|monero|xmr|crypto|aes|rsa|encrypt|decrypt|ransom|shadow|/dev/tcp|/dev/udp|nc -e|iptables|selinux|ld\\.so\\.preload|rootkit\" | sort | uniq | head -n 50"
        
    eval "$CMD_STRINGS"
    echo -e "${BLUE}[Debug CMD] strings \"$FILE_PATH\" ... | grep -E -i \"...\" | sort | uniq | head -n 50${NC}"

    echo -e "\n${YELLOW}[*] (注：仅显示前 50 条去重后的高危字符串特征)${NC}"
    
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# ==============================================================================
# 交互式菜单逻辑引擎
# ==============================================================================
show_menu() {
    clear
    echo -e "${RED}==============================================================${NC}"
    echo -e "${RED}    Linux Emergency Response & Malware Hunting Toolkit        ${NC}"
    echo -e "${RED}           Linux 应急处置与恶意程序定位工具套件 v1.0          ${NC}"
    echo -e "${RED}==============================================================${NC}"
    echo -e "${GREEN}[ Phase 1: 主机基础信息搜集 (Host Recon) ]${NC}"
    echo -e "  ${CYAN}[1]${NC} 一键运行 Phase 1 (系统状态 / 网络外联 / Top进程)"
    echo -e ""
    echo -e "${GREEN}[ Phase 2: 恶意程序定位引擎 (Malware Hunting) ]${NC}"
    echo -e "  ${CYAN}[2]${NC} 基于时间信息定位恶意文件 (排查特定时间落地文件)"
    echo -e "  ${CYAN}[3]${NC} 基于启动时间排查异常进程"
    echo -e "  ${CYAN}[4]${NC} 基于网络 IOC 定位 (瞬时抓取与反 Rootkit 隐藏排查)"
    echo -e "  ${CYAN}[5]${NC} 基于内存特征定位 (利用 dd 安全提取并匹配内存特征)"
    echo -e ""
    echo -e "${GREEN}[ Phase 3: 追踪恶意启动项 (Persistence Tracking) ]${NC}"
    echo -e "  ${CYAN}[6]${NC} 追踪恶意启动项 (深挖持久化机制)"
    echo -e ""
    echo -e "${GREEN}[ Phase 4: 样本静态辅助研判 (Quick Static Triage) ]${NC}"
    echo -e "  ${CYAN}[7]${NC} 样本静态辅助研判 (哈希、脱壳与高危字符串画像)"
    echo -e "${CYAN}==============================================================${NC}"
    echo -e "  ${CYAN}[0]${NC} 退出工具 (Exit)"
    echo -e "${CYAN}==============================================================${NC}"
}

main() {
    check_env
    while true; do
        show_menu
        read -p "请输入对应模块的序号 [0-7]: " choice
        case $choice in
            1) phase1_host_recon ;;
            2) module1_time_based_hunting ;;
            3) module1_5_process_time_hunting ;;
            4) module2_network_ioc_hunting ;;
            5) module3_memory_string_hunting ;;
            6) module4_persistence_tracking ;;
            7) module5_quick_static_triage ;;
            0) 
                echo -e "\n${GREEN}[+] 退出工具，清理现场。Stay Safe!${NC}"
                exit 0 
                ;;
            *) 
                echo -e "${RED}[!] 错误：无效选项，请重新输入！${NC}"
                sleep 1 
                ;;
        esac
    done
}

main "$@"
