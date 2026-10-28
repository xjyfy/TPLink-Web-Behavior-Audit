# -*- coding: utf-8 -*-
"""TL-ER3228ET 日志解析：从原始 syslog/CSV 文本中归一化出结构化字段。"""
import re
from datetime import datetime

_MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
           'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}


def _g(pat, s):
    r = re.search(pat, s)
    return r.group(1).strip() if r else None


def parse_behavior(text):
    """behavior_ctl 行为管控日志内容 -> 结构化字段。"""
    # 严格 IPv4 提取，避免吞进后续乱码字符
    m_ip = re.search(r'主机IP[:：]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
    d = {
        'usergroup': _g(r'用户组[:：]\s*([^,，。]+)', text),
        'host_ip': m_ip.group(1) if m_ip else None,
        'web_group': _g(r'网站分组[:：]\s*([^,，。]+)', text),
        'url': _g(r'网址[:：]\s*([^。]+)', text),
        'app_raw': _g(r'应用类型[:：]\s*([^。]+)', text),
        'dns_query': None,
        'app_category': None,
        'app_name': None,
        'domain': None,
    }
    if d['url']:
        d['domain'] = d['url'].split('/')[0]
    if d['app_raw']:
        r = re.match(r'^(.+?)使用(.+)$', d['app_raw'])
        if r:
            d['app_category'] = r.group(1).strip()
            d['app_name'] = r.group(2).strip()
        else:
            d['app_category'] = d['app_raw']
            d['app_name'] = d['app_raw']
    dns = re.search(r'通过([^,，。]+?)查询([^。]+)', text)
    if dns:
        d['dns_query'] = dns.group(2).strip()

    # app=应用使用; web=带网站分组的网站访问; url=无分组带路径的完整URL; dns=域名查询
    if d['app_raw']:
        d['event_type'] = 'app'
    elif d['web_group']:
        d['event_type'] = 'web'
    elif d['url']:
        d['event_type'] = 'url'
    elif dns:
        d['event_type'] = 'dns'
    else:
        d['event_type'] = 'other'
    return d


def parse_dhcp(text):
    """dhcp_server 日志内容 -> MAC / 分配IP。"""
    return {
        'mac': _g(r'MAC\s*([0-9A-Fa-f][0-9A-Fa-f\-:]{16,17})', text),
        'assigned_ip': _g(r'分配了IP地址\s*([0-9\.]+)', text),
        'event_type': 'dhcp',
    }


def detect_module(text):
    if '用户组:' in text or '用户组：' in text or '主机IP:' in text:
        return 'behavior_ctl'
    if '上网行为:' in text:
        return 'web_usage'
    if 'DHCP服务器为LAN口客户MAC' in text:
        return 'dhcp_server'
    return 'unknown'


def parse_web_usage(text):
    """'上网行为:' 格式日志 -> 结构化字段。"""
    m_ip = re.search(r'a:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
    m_url = re.search(r'网址:(\S+?)(?:\s|。|$)', text)
    m_wg = re.search(r'网站分组:(\S+?)(?:\s|。|$)', text)
    m_app = re.search(r'apptype:(\S+?)\s+使用(\S+?)(?:\s|。|$)', text)
    url = m_url.group(1).rstrip('。') if m_url else None
    d = {
        'usergroup': None,
        'host_ip': m_ip.group(1) if m_ip else None,
        'web_group': m_wg.group(1) if m_wg else None,
        'url': url,
        'app_raw': None,
        'dns_query': None,
        'app_category': None,
        'app_name': None,
        'domain': url.split('/')[0] if url else None,
    }
    if m_app:
        d['app_category'] = m_app.group(1).strip()
        d['app_name'] = m_app.group(2).strip()
    if d['app_category']:
        d['event_type'] = 'app'
    elif d['web_group'] and d['url']:
        d['event_type'] = 'web'
    elif d['url']:
        d['event_type'] = 'url'
    else:
        d['event_type'] = 'other'
    return d


def normalize_message(module, text):
    """根据模块把日志内容解析为结构化 dict。"""
    if module == 'behavior_ctl':
        d = parse_behavior(text)
    elif module == 'web_usage':
        d = parse_web_usage(text)
    elif module == 'dhcp_server':
        d = parse_dhcp(text)
    else:
        d = {'event_type': 'other'}
    return d


def _parse_rfc3164_ts(ts):
    """'Oct 26 17:09:19' -> datetime（年份取当前年）。"""
    m = re.match(r'^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})$', ts.strip())
    if not m:
        return None
    mon = _MONTHS.get(m.group(1))
    if not mon:
        return None
    try:
        return datetime(datetime.now().year, mon, int(m.group(2)),
                       int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def parse_syslog_envelope(raw):
    """解析一条 UDP syslog 报文，返回 (ts_datetime, device_name, message)。
    兼容无信封（纯中文文本）的情况。"""
    if isinstance(raw, bytes):
        s = raw.decode('utf-8', errors='replace').strip()
    else:
        s = raw.strip()

    pri = None
    m = re.match(r'^<(\d+)>(.*)$', s)
    if m:
        pri = int(m.group(1))
        s = m.group(2)

    ts = None
    # RFC3164: "Mon DD HH:MM:SS HOSTNAME tag: msg"
    m = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)$', s)
    if m:
        ts = _parse_rfc3164_ts(m.group(1))
        rest = m.group(2).strip()
        parts = rest.split(' ', 1)
        device = parts[0] if parts else None
        message = parts[1] if len(parts) > 1 else ''
        m2 = re.match(r'^([^:\s]+):\s*(.*)$', message)
        if m2:
            message = m2.group(2)
    else:
        device = None
        message = s
    return ts, device, message


def iso(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')
