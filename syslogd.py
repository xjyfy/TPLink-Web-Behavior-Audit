# -*- coding: utf-8 -*-
"""UDP syslog 接收线程：监听 514，解析后写入 SQLite。
另支持"原始日志分流"：把 上网行为 / behavior_ctl 两类原始日志各写到一个文本文件，
默认关闭，由 data/capture_ctl.txt 标记开启，到截止时间（默认 30 分钟）自动关闭。
"""
import os
import queue
import socket
import threading
import time
from datetime import datetime

import config
import db
import parser
import domain_resolver


# 后台开关：不保存"上网行为"日志（web_usage 类型全部丢弃，不入库、不写分流文件）。
# 由 _settings_watch 线程每 2 秒从 settings 表刷新。
_drop_web_usage = False
# 被禁用的数据来源设备 IP 集合：其上报的 syslog 将被丢弃。
# 由 _disabled_watch 线程每 2 秒从 devices 表刷新，也可由 Web 端切换接口主动刷新。
_disabled_devices = set()
# 排除 IP 集合：命中的访问日志直接丢弃（不入库、不调网站名查询）。
# 由 _excluded_watch 线程每 2 秒从 excluded_ips 表刷新，也可由 Web 端接口主动刷新。
_excluded_ips = set()

# ---- 接收/处理分离：优化 UDP 高峰吞吐、降低接收丢包 ----
# 接收线程只收包入内存队列；worker 线程解析并攒批批量入库，
# 避免单线程 recvfrom→逐条写库 串行导致内核 UDP 接收缓冲溢出丢包。
_RX_QUEUE = queue.Queue(maxsize=50000)
_RX_BATCH = 150          # 攒到该条数批量入库一次
_RX_STATS = {'dropped': 0, 'processed': 0, 'batches': 0}


def refresh_disabled_devices():
    """主动刷新禁用设备集合（设备列表切换启用状态后立即调用）。"""
    global _disabled_devices
    try:
        _disabled_devices = db.get_disabled_devices()
    except Exception as e:
        print("[syslog] 刷新禁用设备失败:", e)


def refresh_excluded_ips():
    """主动刷新排除 IP 集合（后台增删排除 IP 后立即调用）。"""
    global _excluded_ips
    try:
        _excluded_ips = db.get_excluded_ips()
    except Exception as e:
        print("[syslog] 刷新排除 IP 失败:", e)


def _handle_message(message, device_from_pkt, pkt_ts, raw_text, device_ip):
    """解析单条 syslog：返回待入库 rec；被丢弃 / DHCP 返回 None。由 worker 线程调用，攒批入库。"""
    module = parser.detect_module(message)
    # 分流原始日志到文件：置于所有过滤/丢弃判断之前，确保分流的是接收口收到的原始接口日志
    # （含被禁用设备、被 drop 不入库的 web_usage 上网行为），用于佐证接收口收到的行为审计总量。
    _capture_write(module, message)
    # 设备被禁用时丢弃其 syslog（不入库）
    if device_ip in _disabled_devices:
        return None
    # 开关开启时丢弃"上网行为"类型日志（不入库）
    if _drop_web_usage and module == 'web_usage':
        return None
    fields = parser.normalize_message(module, message)
    # 排除 IP 列表命中（终端 host_ip 或来源 device_ip）直接丢弃：不入库、不调网站名查询
    if fields.get('host_ip') in _excluded_ips or device_ip in _excluded_ips:
        return None
    if pkt_ts is not None:
        ts = pkt_ts
    else:
        ts = datetime.now()
    ts_s = parser.iso(ts)

    # DHCP 不进日志表，只更新终端 MAC->IP 映射
    if fields.get('event_type') == 'dhcp':
        db.upsert_host(fields.get('mac'), fields.get('assigned_ip'), ts_s)
        return None

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
    # 异步解析域名/IP -> 网站名（先查24h缓存，命中跳过；未命中并发调接口写缓存），不阻塞入库
    for _d in (rec.get('domain'), rec.get('dns_query')):
        d = domain_resolver.extract_domain(_d)
        if d:
            domain_resolver.submit(d)
    return rec


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


def _disabled_watch():
    """daemon 线程：轮询 devices 表，刷新被禁用的设备 IP 集合。"""
    global _disabled_devices
    while True:
        try:
            _disabled_devices = db.get_disabled_devices()
        except Exception as e:
            print("[syslog] 读取禁用设备失败:", e)
        time.sleep(2)


def _excluded_watch():
    """daemon 线程：轮询 excluded_ips 表，刷新排除 IP 集合。"""
    global _excluded_ips
    while True:
        try:
            _excluded_ips = db.get_excluded_ips()
        except Exception as e:
            print("[syslog] 读取排除 IP 失败:", e)
        time.sleep(2)


def _worker():
    """消费 _RX_QUEUE：解析 + 攒批批量入库，分离接收与写库，避免高峰 UDP 缓冲溢出。"""
    batch = []
    while True:
        try:
            item = _RX_QUEUE.get()
            rec = _handle_message(*item)
            if rec is not None:
                batch.append(rec)
            if len(batch) >= _RX_BATCH or (_RX_QUEUE.qsize() == 0 and batch):
                db.insert_many(batch)
                _RX_STATS['processed'] += len(batch)
                _RX_STATS['batches'] += 1
                batch = []
        except Exception as e:
            print("[syslog] worker 处理异常:", e)
            batch = []  # 避免异常导致本批残留重复入库


def run():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 增大 UDP 接收缓冲，降低高峰内核丢包（Windows 内核可能对上限有约束，用 getsockopt 核对实际值）
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((config.SYSLOG_UDP_HOST, config.SYSLOG_UDP_PORT))
    try:
        rcv = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    except Exception:
        rcv = '?'
    print(f"[syslog] UDP 监听 {config.SYSLOG_UDP_HOST}:{config.SYSLOG_UDP_PORT} SO_RCVBUF={rcv}")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            text = _decode(data)
            pkt_ts, device, message = parser.parse_syslog_envelope(text)
            item = (message, device, pkt_ts, text, addr[0])
            try:
                _RX_QUEUE.put_nowait(item)
            except queue.Full:
                _RX_STATS['dropped'] += 1
                if _RX_STATS['dropped'] % 500 == 1:
                    print(f"[syslog] 警告：接收队列已满，累计丢弃 {_RX_STATS['dropped']} 包（worker 跟不上写库/解析）")
        except Exception as e:
            print("[syslog] 处理异常:", e)


def start_async():
    threading.Thread(target=_settings_watch, daemon=True).start()
    threading.Thread(target=_capture_watch, daemon=True).start()
    threading.Thread(target=_disabled_watch, daemon=True).start()
    threading.Thread(target=_excluded_watch, daemon=True).start()
    threading.Thread(target=_worker, daemon=True).start()
    refresh_disabled_devices()
    refresh_excluded_ips()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
