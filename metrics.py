# -*- coding: utf-8 -*-
"""宿主机 CPU / 内存 / 磁盘 / 网卡实时指标。"""
import time
import psutil

_prev = {'ts': None, 'up': None, 'down': None}


def _net_link_speed():
    """主用网卡链路速率（Mbps）与名称：取在线、非回环、速率最大的网卡。"""
    best, best_name = 0, ''
    try:
        for name, st in psutil.net_if_stats().items():
            if not st.isup or not st.speed or st.speed <= 0:
                continue
            if name.lower().startswith('loopback'):
                continue
            if st.speed > best:
                best, best_name = st.speed, name
    except Exception:
        pass
    return best, best_name


def host_metrics():
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('C:\\')
    net = psutil.net_io_counters()
    now = time.time()
    up_rate = down_rate = 0.0
    if _prev['ts'] is not None:
        dt = now - _prev['ts']
        if dt > 0:
            up_rate = (net.bytes_sent - _prev['up']) / dt
            down_rate = (net.bytes_recv - _prev['down']) / dt
    _prev['ts'] = now
    _prev['up'] = net.bytes_sent
    _prev['down'] = net.bytes_recv
    cores = psutil.cpu_count(logical=False) or psutil.cpu_count() or 0
    net_speed, net_iface = _net_link_speed()
    return {
        'cpu': round(cpu, 1),
        'mem': round(mem.percent, 1),
        'disk': round(disk.percent, 1),
        'up_kbps': round(up_rate / 128, 1),     # bytes/s -> KB/s
        'down_kbps': round(down_rate / 128, 1),
        'cpu_cores': cores,
        'mem_total_gb': round(mem.total / 2 ** 30, 1),
        'disk_total_gb': round(disk.total / 2 ** 30, 1),
        'disk_drive': 'C',
        'net_speed_mbps': net_speed,
        'net_iface': net_iface,
    }
