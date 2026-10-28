# -*- coding: utf-8 -*-
"""UDP syslog 接收线程：监听 514，解析后写入 SQLite。"""
import socket
import threading
from datetime import datetime

import config
import db
import parser


def _handle_message(message, device_from_pkt, pkt_ts, raw_text, device_ip):
    module = parser.detect_module(message)
    fields = parser.normalize_message(module, message)
    if pkt_ts is not None:
        ts = pkt_ts
    else:
        ts = datetime.now()
    ts_s = parser.iso(ts)

    # DHCP 不进日志表，只更新终端 MAC->IP 映射
    if fields.get('event_type') == 'dhcp':
        db.upsert_host(fields.get('mac'), fields.get('assigned_ip'), ts_s)
        return

    rec = {
        'ts': ts_s,
        'device_name': device_from_pkt or 'TL-ER3228ET',
        'device_ip': device_ip,
        'module': module,
        'level': '通知',
        'raw': message,
        'usergroup': fields.get('usergroup'),
        'host_ip': fields.get('host_ip'),
        'mac': fields.get('mac'),
        'assigned_ip': fields.get('assigned_ip'),
        'event_type': fields.get('event_type', 'other'),
        'web_group': fields.get('web_group'),
        'url': fields.get('url'),
        'domain': fields.get('domain'),
        'app_category': fields.get('app_category'),
        'app_name': fields.get('app_name'),
        'dns_query': fields.get('dns_query'),
    }
    db.insert_log(rec)


def _decode(data):
    """路由器(TP-Link)多为 GBK，先试 GBK，失败再退 UTF-8。"""
    for enc in ('gbk', 'utf-8'):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='replace')


def run():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config.SYSLOG_UDP_HOST, config.SYSLOG_UDP_PORT))
    print(f"[syslog] UDP 监听 {config.SYSLOG_UDP_HOST}:{config.SYSLOG_UDP_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            text = _decode(data)
            pkt_ts, device, message = parser.parse_syslog_envelope(text)
            _handle_message(message, device, pkt_ts, text, addr[0])
        except Exception as e:
            print("[syslog] 处理异常:", e)


def start_async():
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
