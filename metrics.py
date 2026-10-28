# -*- coding: utf-8 -*-
"""宿主机 CPU / 内存 / 磁盘 / 网卡实时指标。"""
import time
import psutil

_prev = {'ts': None, 'up': None, 'down': None}


def host_metrics():
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('C:\\').percent
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
    return {
        'cpu': round(cpu, 1),
        'mem': round(mem, 1),
        'disk': round(disk, 1),
        'up_kbps': round(up_rate / 128, 1),     # bytes/s -> KB/s
        'down_kbps': round(down_rate / 128, 1),
    }
