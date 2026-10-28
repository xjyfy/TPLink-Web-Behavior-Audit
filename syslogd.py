# -*- coding: utf-8 -*-
"""UDP syslog 接收线程：监听 514，解析后写入 SQLite。
另支持"原始日志分流"：把 上网行为 / behavior_ctl 两类原始日志各写到一个文本文件，
默认关闭，由 data/capture_ctl.txt 标记开启，到截止时间（默认 30 分钟）自动关闭。
"""
import os
import socket
import threading
import time
from datetime import datetime

import config
import db
import parser


# 后台开关：不保存"上网行为"日志（web_usage 类型全部丢弃，不入库、不写分流文件）。
# 由 _settings_watch 线程每 2 秒从 settings 表刷新。
_drop_web_usage = False


def _handle_message(message, device_from_pkt, pkt_ts, raw_text, device_ip):
    module = parser.detect_module(message)
    # 开关开启时丢弃"上网行为"类型日志
    if _drop_web_usage and module == 'web_usage':
        return
    _capture_write(module, message)
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


# ============ 原始日志分流（可选，默认关闭） ============
# 控制方式：data/capture_ctl.txt 存在即开启，其内容为截止时间戳（秒）；到点自动关闭并删除标记。
# 分流入文件不影响正常入库，任何写入异常都不影响主流程。
CAPTURE_CTL = os.path.join(config.DATA_DIR, 'capture_ctl.txt')
CAPTURE_DIR = os.path.join(config.DATA_DIR, 'capture')
_CAPTURE_FILE = {
    'web_usage': '上网行为.txt',
    'behavior_ctl': 'behavior_ctl.txt',
}
_capture = {'on': False, 'fhs': {}, 'end': 0.0}


def _capture_write(module, message):
    """把原始日志按类型追加到对应文件；仅处理 web_usage / behavior_ctl 两类。"""
    if not _capture['on']:
        return
    fname = _CAPTURE_FILE.get(module)
    if not fname:
        return
    try:
        fh = _capture['fhs'].get(module)
        if fh is None:
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            fh = open(os.path.join(CAPTURE_DIR, fname), 'a', encoding='utf-8')
            _capture['fhs'][module] = fh
        fh.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' ' + message.rstrip('\n') + '\n')
        fh.flush()
    except Exception as e:
        print("[capture] 写入失败:", e)


def _capture_open_all():
    try:
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        for m in _CAPTURE_FILE:
            if m not in _capture['fhs']:
                _capture['fhs'][m] = open(os.path.join(CAPTURE_DIR, _CAPTURE_FILE[m]), 'a', encoding='utf-8')
    except Exception as e:
        print("[capture] 打开文件失败:", e)


def _capture_close():
    for m, fh in list(_capture['fhs'].items()):
        try:
            fh.close()
        except Exception:
            pass
    _capture['fhs'].clear()


def _capture_watch():
    """daemon 线程：轮询控制标记，开启/自动关闭原始日志分流。"""
    while True:
        try:
            ctl = os.path.exists(CAPTURE_CTL)
            if ctl and not _capture['on']:
                end = 0.0
                try:
                    with open(CAPTURE_CTL, encoding='utf-8') as f:
                        end = float((f.read() or '').strip() or 0)
                except Exception:
                    end = 0.0
                _capture['end'] = end
                _capture['on'] = True
                _capture_open_all()
                print("[capture] 已开启原始日志分流，截止",
                      datetime.fromtimestamp(end).strftime('%H:%M:%S') if end else '无')
            elif ctl and _capture['on'] and _capture['end'] and time.time() >= _capture['end']:
                _capture_close()
                _capture['on'] = False
                try:
                    os.remove(CAPTURE_CTL)
                except Exception:
                    pass
                print("[capture] 分流已到截止时间，文件已关闭")
            elif not ctl and _capture['on']:
                _capture_close()
                _capture['on'] = False
        except Exception as e:
            print("[capture] 监控异常:", e)
        time.sleep(1)


def _settings_watch():
    """daemon 线程：轮询 settings 表，刷新"不保存上网行为日志"开关到内存。"""
    global _drop_web_usage
    while True:
        try:
            _drop_web_usage = str(db.get_setting('drop_web_usage', '0')) == '1'
        except Exception as e:
            print("[settings] 读取异常:", e)
        time.sleep(2)


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
    threading.Thread(target=_settings_watch, daemon=True).start()
    threading.Thread(target=_capture_watch, daemon=True).start()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
