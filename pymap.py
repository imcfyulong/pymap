#yu10 - Network scanning tool
from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP, TCP
import argparse
import socket
from threading import Thread
import re
from concurrent.futures import ThreadPoolExecutor  # 引入线程池控制并发

# 全局配置
MAX_THREADS = 50  # 最大并发线程数，避免系统崩溃
TIMEOUT = 3       # 扫描超时时间（秒）
BANNER_TIMEOUT = 3 # Banner探测超时时间

# 通用端口解析函数
def parse_ports(port_str):
    """解析端口字符串，返回端口列表"""
    ports = []
    # 处理逗号分隔（如80,443,8080）
    if ',' in port_str:
        port_list = port_str.split(',')
        for p in port_list:
            try:
                port = int(p)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                print(f"警告：无效端口号 {p}，已跳过")
    # 处理范围分隔（如1-100）
    elif '-' in port_str:
        try:
            start, end = port_str.split('-')
            start_port = int(start)
            end_port = int(end)
            if 1 <= start_port <= end_port <= 65535:
                ports = list(range(start_port, end_port + 1))  # 修复左闭右开漏扫问题
            else:
                print("警告：端口范围超出1-65535，已跳过")
        except ValueError:
            print(f"警告：无效端口范围 {port_str}，已跳过")
    # 处理全端口
    elif port_str.lower() == 'all':
        ports = list(range(1, 65536))  # 修复漏扫65535端口
    # 处理单个端口
    else:
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                print("警告：端口号超出1-65535，已跳过")
        except ValueError:
            print(f"警告：无效端口号 {port_str}，已跳过")
    return ports

# 验证IP格式
def is_valid_ip(ip):
    """验证IP地址合法性"""
    pattern = r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    return re.match(pattern, ip) is not None

#tcp全开扫描
def tcp_all(ip,port):
    try:
        #创建一个TCP SYN包
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        #用sr来接收返回的数据， _表示占位（不需要解析数据包）
        resp,_ = sr(packet, timeout=TIMEOUT, verbose=0)

        #如果没有响应
        if not resp:
            print(f"{ip}:{port} TCP 端口过滤/关闭")
        else:
            #遍历响应的数据包
            for snd, rcv in resp:
                #检测是否有TCP响应的报文，以0x12（即ACK+SYN）为标志
                if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:
                    #ACK+RST包，主动断开连接
                    send_rst = sr(IP(dst=ip)/TCP(dport=port, flags="AR"), timeout=TIMEOUT, verbose=0)
                    print(f"{ip}:{port} TCP 端口开放")
                    break
            else:
                #如果没有SYN+ACK响应
                print(f"{ip}:{port} TCP 端口关闭")
    except Exception as e:
        print(f"{ip}:{port} TCP扫描出错: {e}")

#TCP SYN半开扫描
def tcp_half(ip,port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        resp, _ = sr(packet, timeout=TIMEOUT, verbose=0)

        if not resp:
            #无响应：端口过滤
            print(f"{ip}:{port} SYN 端口过滤")
        elif resp[0][1].haslayer(TCP):
            tcp_flags = resp[0][1][TCP].flags
            if tcp_flags == 0x12:
                #SYN+ACK：端口开放，发送RST断开
                send_rst = sr(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=TIMEOUT, verbose=0)
                print(f"{ip}:{port} SYN 端口开放")
            elif tcp_flags == 0x04:
                #RST：端口关闭
                print(f"{ip}:{port} SYN 端口关闭")
            else:
                #其他标志：未知状态
                print(f"{ip}:{port} SYN 端口状态未知")
        else:
            print(f"{ip}:{port} SYN 无TCP响应")
    except IndexError:
        print(f"{ip}:{port} SYN扫描响应包解析错误")
    except Exception as e:
        print(f"{ip}:{port} SYN扫描出错: {e}")

#ICMP 扫描（主机存活检测，无端口概念）
def icmp_scan(ip, port=None):  # port参数保留以兼容调用，实际无意义
    try:
        packet = IP(dst=ip)/ICMP()
        #sr1适用于ICMP扫描，返回单个响应包
        resp = sr1(packet, timeout=TIMEOUT, verbose=0)

        if not resp:
            print(f"{ip} ICMP 主机不可达/过滤")
        elif resp.haslayer(ICMP) and resp[ICMP].type == 0:
            #ICMP type 0 = Echo Reply（主机存活）
            print(f"{ip} ICMP 主机存活")
        else:
            print(f"{ip} ICMP 非Echo Reply响应")
    except Exception as e:
        print(f"{ip} ICMP扫描出错: {e}")

#UDP 扫描
def udp_scan(ip,port):
    try:
        packet = IP(dst=ip)/UDP(dport=port)
        resp,_ = sr(packet, timeout=TIMEOUT, verbose=0)

        if not resp:
            #UDP无响应：端口可能开放/过滤
            print(f"{ip}:{port} UDP 端口可能开放/过滤")
        else:
            for snd, rcv in resp:
                if rcv.haslayer(ICMP):
                    icmp_type = rcv[ICMP].type
                    icmp_code = rcv[ICMP].code
                    if icmp_type == 3 and icmp_code == 3:
                        #ICMP 3/3 = Port Unreachable（端口关闭）
                        print(f"{ip}:{port} UDP 端口关闭")
                    else:
                        #其他ICMP错误：端口过滤
                        print(f"{ip}:{port} UDP 端口过滤")
                else:
                    #有UDP响应：端口开放
                    print(f"{ip}:{port} UDP 端口开放")
    except Exception as e:
        print(f"{ip}:{port} UDP扫描出错: {e}")

#banner探测
def banner(ip,port):
    try:
        #创建套接字对象
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #设置超时时间
        s.settimeout(BANNER_TIMEOUT)
        #创建socket链接
        s.connect((ip,port))
        #发送适配性探测数据（不同服务兼容）
        probe_data = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
        s.send(probe_data)
        #接收服务器返回的，最多1024个字节
        banner = s.recv(1024)
        #关闭套接字链接
        s.close()

        if banner:
            #解码并清理乱码
            clean_banner = banner.decode('utf-8', errors='ignore').strip()
            print(f"{ip}:{port} Banner: {clean_banner}")
        else:
            print(f"{ip}:{port} Banner: 无返回数据")
    except socket.timeout:
        print(f"{ip}:{port} Banner探测：超时")
    except ConnectionRefusedError:
        print(f"{ip}:{port} Banner探测：连接被拒绝")
    except Exception as e:
        print(f"{ip}:{port} Banner探测出错: {e}")

def main():
    #定义参数使用帮助
    usage = "python pymap.py -i <ip> -p <port> <Scanning method>\n示例: python pymap.py -i 192.168.1.1 -p 80,443 -sT"
    #定义ArgumentParser对象，用于解析命令行参数
    parser = argparse.ArgumentParser(description="Network scanning tool (optimized)", usage=usage)
    #添加-i或者--ip,指定IP地址（必填）
    parser.add_argument("-i", "--ip", action="store", dest="ip", help="目标IP地址", required=True)
    # 添加-p或者--port,指定port端口（必填）
    parser.add_argument("-p", "--port", action="store", dest="port", help="目标端口(支持: 单个/范围/逗号分隔/all)", required=True)
    # 添加一个互斥数组，用于指定扫描方法
    method_group = parser.add_mutually_exclusive_group(required=True)
    ## 添加-sT扫描参数，用于TCP全开扫描;布尔开关
    method_group.add_argument("-sT", action="store_true", help="TCP 全开扫描")
    method_group.add_argument("-sS", action="store_true", help="TCP SYN 半开扫描")
    method_group.add_argument("-sP", action="store_true", help="ICMP 主机存活扫描")
    method_group.add_argument("-sU", action="store_true", help="UDP 扫描")
    method_group.add_argument("-sB", action="store_true", help="Banner 探测")

    #解析命令行参数，然后保存在args中
    args = parser.parse_args()
    #指定ip和port
    ip = args.ip
    port_str = args.port

    # 验证IP格式
    if not is_valid_ip(ip):
        print(f"错误：无效的IP地址 {ip}")
        return

    # 解析端口
    ports = parse_ports(port_str)
    if not ports:
        print("错误：未解析到有效端口，请检查端口格式")
        return
    print(f"=== 开始扫描 {ip}，端口列表：{ports} ===")

    # 初始化线程池
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # ===================== TCP全开扫描 (-sT) =====================
        if args.sT:
            for port in ports:
                executor.submit(tcp_all, ip, port)
        # ===================== TCP SYN半开扫描 (-sS) =====================
        elif args.sS:
            # SYN扫描需要root权限提示
            import os
            if os.geteuid() != 0 and os.name != 'nt':
                print("警告：SYN半开扫描在Linux下需要root权限，可能扫描失败！")
            for port in ports:
                executor.submit(tcp_half, ip, port)
        # ===================== ICMP扫描 (-sP) =====================
        elif args.sP:
            # ICMP扫描忽略端口，直接扫描主机
            executor.submit(icmp_scan, ip)
        # ===================== UDP扫描 (-sU) =====================
        elif args.sU:
            for port in ports:
                executor.submit(udp_scan, ip, port)
        # ===================== Banner探测 (-sB) =====================
        elif args.sB:
            for port in ports:
                executor.submit(banner, ip, port)

    print(f"=== {ip} 扫描任务提交完成，等待结果输出 ===")

if __name__ == '__main__':
    main()
