# PyMap - Nmap部分功能复刻工具-基于python

基于 Python 实现的轻量级 Nmap 核心功能复刻工具，覆盖 Nmap 常用的端口扫描、主机存活探测、服务识别等能力，通过原生 Python 库 + Scapy 实现底层网络操作。

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2743%27%20height=%2710%27/%3e)![image](https://img.shields.io/badge/Python-3.6%2B-brightgreen.svg)

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2741%27%20height=%2710%27/%3e)![image](https://img.shields.io/badge/License-MIT-blue.svg)

![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2745%27%20height=%2710%27/%3e)![image](https://img.shields.io/badge/Scapy-2.5.0%2B-orange.svg)

## 🌟 功能特性

复刻 Nmap 部分核心功能，针对网络扫描场景解决实际问题：

- **TCP 全开扫描 (-sT)**：复刻 Nmap `-sT`，基于 TCP 三次握手检测端口开放状态
- **TCP SYN 半开扫描 (-sS)**：复刻 Nmap `-sS`，隐蔽性更高的半开扫描（无需完成三次握手）
- **ICMP 主机存活扫描 (-sP)**：复刻 Nmap `-sP`，快速检测目标主机是否存活
- **UDP 扫描 (-sU)**：复刻 Nmap `-sU`，识别 UDP 端口开放 / 关闭 / 过滤状态
- **Banner 探测 (-sB)**：复刻 Nmap `-sV` 轻量版，获取开放端口的服务 Banner 信息
- **灵活的端口指定**：支持单个端口、范围、多端口、全端口（复刻 Nmap 端口指定语法）
- **并发控制**：解决原生多线程扫描资源耗尽问题，保证扫描稳定性
- **异常容错**：解决 IP / 端口格式错误、网络超时、权限不足等常见扫描问题

## 🛠️ 核心技术实现

### 1. 底层网络数据包操作 - Scapy

**解决的问题**：原生 socket 无法灵活构造 / 解析网络数据包，无法实现 SYN 半开、ICMP 定制等底层扫描逻辑

**技术实现**：

- 基于 Scapy 的`IP()`/`TCP()`/`UDP()`/`ICMP()`构造定制化网络数据包（如 SYN 包、Ping 包）
- 通过`sr()`/`sr1()`发送并接收数据包，解析响应包的标志位（如 SYN+ACK=0x12、RST=0x04）
- 屏蔽 Scapy 冗余输出（`verbose=0`），提升扫描结果可读性

### 2. 并发扫描控制 - ThreadPoolExecutor

**解决的问题**：原生多线程无限制创建（如全端口扫描创建 65535 个线程）导致系统崩溃

**技术实现**：

- 引入`concurrent.futures.ThreadPoolExecutor`限制最大并发线程数（默认 50）
- 统一管理扫描任务提交与执行，避免线程资源耗尽
- 兼容不同扫描方式的并发需求，保证扫描效率与系统稳定性

### 3. 端口解析与校验 - 通用函数封装

**解决的问题**：重复的端口解析逻辑（逗号 / 范围 /all）导致代码冗余、易出错

**技术实现**：

- 封装`parse_ports()`通用函数，统一处理各类端口输入格式
- 增加端口合法性校验（1-65535 范围），过滤无效端口并给出提示
- 修复`range()`左闭右开特性导致的端口漏扫问题（如`1-100`完整扫描 100 个端口）

### 4. 网络异常处理 - 分层异常捕获

**解决的问题**：网络超时、连接拒绝、权限不足等异常导致扫描中断

**技术实现**：

- 针对不同扫描场景分层捕获异常（`socket.timeout`/`ConnectionRefusedError`/`IndexError`等）
- 对 SYN 扫描增加 ROOT 权限检测（Linux），给出明确的权限提示
- 统一扫描超时时间配置（`TIMEOUT`），避免单端口扫描阻塞整体流程

### 5. 服务 Banner 识别 - Socket + 定制化探测

**解决的问题**：原生 socket 发送固定数据无法适配不同服务的 Banner 返回规则

**技术实现**：

- 基于`socket.socket()`建立 TCP 连接，发送 HTTP 标准探测包（兼容多数服务）
- 对返回数据进行 UTF-8 解码（忽略乱码），输出可读的 Banner 信息
- 缩短 Banner 探测超时时间（3 秒），提升批量扫描效率

### 6. 命令行参数解析 - argparse

**解决的问题**：手动解析命令行参数易出错、扩展性差

**技术实现**：

- 基于`argparse`构建标准化参数解析器，支持必填参数校验（`required=True`）
- 实现互斥参数组（扫描方式二选一），复刻 Nmap 的参数风格
- 增加 IP 格式正则校验（`is_valid_ip()`），过滤无效 IP 输入

## 📋 环境要求

### 系统要求

- Linux/macOS：SYN 半开扫描需要 ROOT 权限
- Windows：部分功能（如 SYN 扫描）受系统限制，建议使用管理员权限运行

### 依赖安装

```bash
# 安装核心依赖
pip install scapy argparse

# Linux额外依赖（解决Scapy底层抓包问题）
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel    # CentOS/RHEL
```

## 🚀 使用方法

### 基本语法

```bash
python pymap.py -i <目标IP> -p <端口> <扫描方式>
```

### 参数说明

| 参数        | 功能（对应 Nmap）    | 示例                                          |
| ----------- | -------------------- | --------------------------------------------- |
| `-i/--ip`   | 目标 IP 地址（必填） | `-i 192.168.1.1`                              |
| `-p/--port` | 目标端口（必填）     | `-p 80` / `-p 1-100` / `-p 80,443` / `-p all` |
| `-sT`       | TCP 全开扫描         | `-p 80 -sT`                                   |
| `-sS`       | TCP SYN 半开扫描     | `-p 1-100 -sS`                                |
| `-sP`       | ICMP 主机存活扫描    | `-p all -sP`                                  |
| `-sU`       | UDP 扫描             | `-p 53 -sU`                                   |
| `-sB`       | Banner 探测          | `-p 80,443 -sB`                               |

## 📝 扫描结果说明（对标 Nmap 输出）

| 输出信息                | 含义                                   |                              |
| ----------------------- | -------------------------------------- | ---------------------------- |
| `TCP 端口开放`          | open（端口开放，可建立连接）           |                              |
| `TCP 端口关闭`          | closed（端口关闭，主动拒绝连接）       |                              |
| `TCP 端口过滤/关闭`     | filtered（端口被防火墙过滤，无响应）   |                              |
| `SYN 端口开放`          | open（SYN+ACK 响应，端口开放）         |                              |
| `SYN 端口过滤`          | filtered（无响应，防火墙过滤）         |                              |
| `ICMP 主机存活`         | up（主机响应 Ping，存活）              |                              |
| `UDP 端口可能开放/过滤` | open                                   | filtered（无响应，无法确定） |
| `UDP 端口关闭`          | closed（ICMP Port Unreachable）        |                              |
| `Banner: xxx`           | 服务版本信息（对应 Nmap service info） |                              |

## ⚠️ 注意事项

1. **权限兼容**
   - Linux/macOS 下 SYN 扫描（`-sS`）必须使用`sudo`
   - Windows 需管理员权限运行，部分底层网络操作可能受限
2. **法律合规**：仅可扫描授权目标，未经授权的网络扫描违反《网络安全法》等法律法规
3. **性能调优**：可修改代码中`MAX_THREADS`调整并发数（建议 50-200），平衡扫描速度与稳定性
4. **结果差异**：相比 Nmap，本工具未实现指纹库、操作系统识别等高级功能，适合轻量扫描场景

## 🛠️ 自定义配置

可修改代码头部的全局配置参数，适配不同扫描场景：

```python
# 全局配置（可根据需求调整）
MAX_THREADS = 50  # 最大并发线程数（建议50-200）
TIMEOUT = 3       # 扫描超时时间（秒）
BANNER_TIMEOUT = 3 # Banner探测超时时间（秒）
```

------

### 免责声明

本工具仅用于网络安全学习和授权测试，使用者应遵守当地法律法规，因滥用本工具造成的一切后果由使用者自行承担。
