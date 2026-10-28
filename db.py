# -*- coding: utf-8 -*-
"""SQLite 数据访问层。"""
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  device_name TEXT,
  device_ip TEXT,
  module TEXT,
  level TEXT,
  raw TEXT,
  usergroup TEXT,
  host_ip TEXT,
  mac TEXT,
  assigned_ip TEXT,
  event_type TEXT,
  web_group TEXT,
  url TEXT,
  domain TEXT,
  app_category TEXT,
  app_name TEXT,
  dns_query TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_host ON logs(host_ip);
CREATE INDEX IF NOT EXISTS idx_event ON logs(event_type);
CREATE INDEX IF NOT EXISTS idx_domain ON logs(domain);
CREATE INDEX IF NOT EXISTS idx_appcat ON logs(app_category);
CREATE INDEX IF NOT EXISTS idx_appname ON logs(app_name);
-- 复合索引：时间过滤 + 聚合列（覆盖最常见的查询模式）
CREATE INDEX IF NOT EXISTS idx_ts_domain ON logs(ts, domain);
CREATE INDEX IF NOT EXISTS idx_ts_appname ON logs(ts, app_name);
CREATE INDEX IF NOT EXISTS idx_ts_host ON logs(ts, host_ip);
CREATE INDEX IF NOT EXISTS idx_ts_event ON logs(ts, event_type);
CREATE INDEX IF NOT EXISTS idx_ts_appcat ON logs(ts, app_category);

CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id=1),
  username TEXT,
  pw_hash TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  mac TEXT PRIMARY KEY,
  ip TEXT,
  hostname TEXT DEFAULT '',
  first_seen TEXT,
  last_seen TEXT,
  note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS devices (
  device_ip TEXT PRIMARY KEY,
  device_name TEXT,
  custom_name TEXT DEFAULT ''
);
"""


def _conn():
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    c = _conn()
    c.executescript(_SCHEMA)
    # 迁移：旧库加 hostname 列
    try:
        c.execute("ALTER TABLE hosts ADD COLUMN hostname TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    # 默认管理员
    row = c.execute("SELECT id FROM admin WHERE id=1").fetchone()
    if not row:
        c.execute("INSERT INTO admin(id, username, pw_hash) VALUES (1,?,?)",
                  (config.DEFAULT_ADMIN_USER, hash_pw(config.DEFAULT_ADMIN_PASS)))
    c.commit()
    c.close()


def hash_pw(pw, salt=None):
    if salt is None:
        salt = os.urandom(8).hex()
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return salt + '$' + h.hex()


def verify_pw(pw, stored):
    try:
        salt, _ = stored.split('$', 1)
        return hash_pw(pw, salt) == stored
    except Exception:
        return False


def get_admin():
    c = _conn()
    r = c.execute("SELECT username, pw_hash FROM admin WHERE id=1").fetchone()
    c.close()
    return dict(r) if r else None


def change_password(old_pw, new_pw):
    a = get_admin()
    if not a or not verify_pw(old_pw, a['pw_hash']):
        return False
    c = _conn()
    c.execute("UPDATE admin SET pw_hash=? WHERE id=1", (hash_pw(new_pw),))
    c.commit()
    c.close()
    return True


def insert_log(rec):
    """rec: dict with normalized fields + ts + device_name/ip/module/level/raw."""
    c = _conn()
    c.execute("""INSERT INTO logs
        (ts, device_name, device_ip, module, level, raw, usergroup, host_ip,
         mac, assigned_ip, event_type, web_group, url, domain,
         app_category, app_name, dns_query)
        VALUES (:ts,:device_name,:device_ip,:module,:level,:raw,:usergroup,:host_ip,
                :mac,:assigned_ip,:event_type,:web_group,:url,:domain,
                :app_category,:app_name,:dns_query)""", rec)
    c.commit()
    c.close()


def insert_many(rows):
    c = _conn()
    c.executemany("""INSERT INTO logs
        (ts, device_name, device_ip, module, level, raw, usergroup, host_ip,
         mac, assigned_ip, event_type, web_group, url, domain,
         app_category, app_name, dns_query)
        VALUES (:ts,:device_name,:device_ip,:module,:level,:raw,:usergroup,:host_ip,
                :mac,:assigned_ip,:event_type,:web_group,:url,:domain,
                :app_category,:app_name,:dns_query)""", rows)
    c.commit()
    c.close()


def query_logs(start=None, end=None, host_ip=None, event_type=None,
               app_category=None, app_name=None, keyword=None, page=1, size=50):
    where, params = [], []
    if start:
        where.append("ts >= ?"); params.append(start)
    if end:
        where.append("ts <= ?"); params.append(end)
    if host_ip:
        where.append("host_ip = ?"); params.append(host_ip)
    if event_type:
        where.append("event_type = ?"); params.append(event_type)
    if app_category:
        where.append("app_category = ?"); params.append(app_category)
    if app_name:
        where.append("app_name = ?"); params.append(app_name)
    if keyword:
        where.append("(raw LIKE ? OR url LIKE ? OR domain LIKE ? OR app_name LIKE ? OR host_ip LIKE ?)")
        k = '%' + keyword + '%'
        params += [k, k, k, k, k]
    w = ("WHERE " + " AND ".join(where)) if where else ""
    c = _conn()
    total = c.execute(f"SELECT COUNT(*) n FROM logs {w}", params).fetchone()['n']
    rows = c.execute(f"""SELECT * FROM logs {w} ORDER BY id DESC LIMIT ? OFFSET ?""",
                    params + [size, (page - 1) * size]).fetchall()
    c.close()
    return total, [dict(r) for r in rows]


def summary():
    c = _conn()
    today = datetime.now().strftime('%Y-%m-%d')
    total_today = c.execute("SELECT COUNT(*) n FROM logs WHERE ts LIKE ?", (today + '%',)).fetchone()['n']
    hosts_today = c.execute("SELECT COUNT(DISTINCT host_ip) n FROM logs WHERE ts LIKE ? AND host_ip IS NOT NULL", (today + '%',)).fetchone()['n']
    domains_today = c.execute("SELECT COUNT(DISTINCT domain) n FROM logs WHERE ts LIKE ? AND event_type='web'", (today + '%',)).fetchone()['n']
    total_all = c.execute("SELECT COUNT(*) n FROM logs").fetchone()['n']
    c.close()
    return {'total_today': total_today, 'hosts_today': hosts_today,
            'domains_today': domains_today, 'total_all': total_all}


def _range_where(start=None, end=None, alias=""):
    p = alias + "." if alias else ""
    where, params = [], []
    if start:
        where.append(f"{p}ts >= ?"); params.append(start)
    if end:
        where.append(f"{p}ts <= ?"); params.append(end)
    return ("WHERE " + " AND ".join(where)) if where else "", params


def trend(hours=24):
    c = _conn()
    rows = c.execute("""SELECT substr(ts,1,13) hr, COUNT(*) n FROM logs
        GROUP BY hr ORDER BY hr DESC LIMIT ?""", (hours,)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    for i in range(hours - 1, -1, -1):
        hr = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
    return out


def online_trend(hours=24):
    """每小时在线终端数（去重 host_ip）。"""
    c = _conn()
    rows = c.execute("""SELECT substr(ts,1,13) hr, COUNT(DISTINCT host_ip) n FROM logs
        WHERE host_ip IS NOT NULL GROUP BY hr ORDER BY hr DESC LIMIT ?""", (hours,)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    for i in range(hours - 1, -1, -1):
        hr = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
    return out


def _cond(w, extra):
    return (w + " AND " + extra) if w else ("WHERE " + extra)


def top_hosts(limit=10, start=None, end=None):
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT host_ip k, COUNT(*) n FROM logs
        {_cond(w, "host_ip IS NOT NULL")} GROUP BY host_ip ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def top_domains(limit=10, start=None, end=None):
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT domain k, COUNT(*) n FROM logs
        {_cond(w, "event_type IN ('web','url') AND domain IS NOT NULL")} GROUP BY domain ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def app_categories(start=None, end=None):
    """应用类别分布，排除'网络基础协议'（单独走协议TOP）。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, COUNT(*) n FROM logs
        {_cond(w, "event_type='app' AND app_category IS NOT NULL AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC LIMIT 10""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def app_categories_all(start=None, end=None):
    """应用类别全量（不分页）。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, COUNT(*) n FROM logs
        {_cond(w, "event_type='app' AND app_category IS NOT NULL AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def top_apps(limit=10, start=None, end=None):
    """应用TOP，排除 http/https（网络基础协议类，单独走协议TOP）。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, COUNT(*) n FROM logs
        {_cond(w, "event_type='app' AND app_name IS NOT NULL AND lower(app_name) NOT IN ('http','https')")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def protocol_top(start=None, end=None):
    """网络协议TOP：仅日志里有明确协议名的（网络基础协议下的 app_name，如 HTTP/HTTPS/NTP）。
    域名类访问不并入，统一在热门网站图表展示。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""
        SELECT app_name k, COUNT(*) n FROM logs
        {_cond(w, "event_type='app' AND app_category='网络基础协议' AND app_name IS NOT NULL")}
        GROUP BY app_name
        ORDER BY n DESC LIMIT 12""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def protocol_top_all(start=None, end=None):
    """网络协议全量（不分页）。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""
        SELECT app_name k, COUNT(*) n FROM logs
        {_cond(w, "event_type='app' AND app_category='网络基础协议' AND app_name IS NOT NULL")}
        GROUP BY app_name
        ORDER BY n DESC""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def export_rows(start=None, end=None):
    where, params = [], []
    if start:
        where.append("ts >= ?"); params.append(start)
    if end:
        where.append("ts <= ?"); params.append(end)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    c = _conn()
    rows = c.execute(f"""SELECT ts,device_name,module,level,host_ip,event_type,
        web_group,domain,url,app_category,app_name,raw FROM logs {w} ORDER BY id ASC""", params).fetchall()
    c.close()
    return [dict(r) for r in rows]


def delete_range(start, end):
    c = _conn()
    cur = c.execute("DELETE FROM logs WHERE ts >= ? AND ts <= ?", (start, end))
    n = cur.rowcount
    c.commit()
    c.close()
    return n


def prune(days):
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    c = _conn()
    cur = c.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
    n = cur.rowcount
    c.commit()
    c.close()
    return n


# ---------- 终端（MAC -> IP 动态映射 + 备注） ----------
def upsert_host(mac, ip, ts=None):
    if not mac:
        return
    ts = ts or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 反向解析主机名（DNS / NetBIOS）
    hostname = _resolve_hostname(ip)
    c = _conn()
    row = c.execute("SELECT mac, ip FROM hosts WHERE mac=?", (mac,)).fetchone()
    if row:
        # IP 变了才重新解析主机名
        old = dict(row)
        new_hostname = hostname if old['ip'] != ip else None
        if new_hostname:
            c.execute("UPDATE hosts SET ip=?, last_seen=?, hostname=? WHERE mac=?", (ip, ts, new_hostname, mac))
        else:
            c.execute("UPDATE hosts SET ip=?, last_seen=? WHERE mac=?", (ip, ts, mac))
    else:
        c.execute("INSERT INTO hosts(mac, ip, hostname, first_seen, last_seen, note) VALUES (?,?,?,?,?,'')",
                  (mac, ip, hostname or '', ts, ts))
    c.commit()
    c.close()


def _resolve_hostname(ip):
    """反向解析 IP 对应的主机名，失败返回空字符串。"""
    import socket
    if not ip or not ip[0].isdigit():
        return ''
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ''


def list_hosts(keyword=None):
    w, p = "", []
    if keyword:
        w = "WHERE mac LIKE ? OR ip LIKE ? OR note LIKE ?"
        k = '%' + keyword + '%'
        p = [k, k, k]
    c = _conn()
    rows = c.execute(f"SELECT * FROM hosts {w} ORDER BY last_seen DESC", p).fetchall()
    cutoff = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    out = []
    for r in rows:
        d = dict(r)
        online = c.execute(
            "SELECT 1 FROM logs WHERE host_ip=? AND ts>=? LIMIT 1",
            (d.get('ip'), cutoff)).fetchone()
        d['online'] = bool(online)
        out.append(d)
    c.close()
    return out


def set_host_note(mac, note):
    c = _conn()
    c.execute("UPDATE hosts SET note=? WHERE mac=?", (note, mac))
    c.commit()
    c.close()


def host_note_map_by_ip():
    """返回 {ip: note}，用于日志列表里按 IP 补备注。"""
    c = _conn()
    rows = c.execute("SELECT ip, note FROM hosts WHERE note IS NOT NULL AND note != ''").fetchall()
    c.close()
    return {r['ip']: r['note'] for r in rows}


# ---------- 数据来源设备 ----------
def list_devices():
    """从 logs 表聚合出所有上报设备，LEFT JOIN devices 取自定义名称。"""
    c = _conn()
    rows = c.execute("""
        SELECT l.device_ip, l.device_name, COUNT(*) n, MAX(l.ts) last_seen,
               COALESCE(d.custom_name, '') custom_name
        FROM logs l LEFT JOIN devices d ON l.device_ip = d.device_ip
        WHERE l.device_ip IS NOT NULL AND l.device_ip != ''
        GROUP BY l.device_ip
        ORDER BY n DESC""").fetchall()
    c.close()
    return [dict(r) for r in rows]


def set_device_name(device_ip, custom_name):
    c = _conn()
    c.execute("""INSERT INTO devices(device_ip, custom_name) VALUES(?,?)
        ON CONFLICT(device_ip) DO UPDATE SET custom_name=excluded.custom_name""",
        (device_ip, custom_name))
    c.commit()
    c.close()


# ---------- 系统设置 ----------
def get_setting(key, default=None):
    c = _conn()
    row = c.execute("CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)").fetchall()
    r = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
    c.close()
    return r[0] if r else default


def set_setting(key, value):
    c = _conn()
    c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
              (key, str(value)))
    c.commit()
    c.close()


# ---------- 应用图标缓存 ----------
def init_icons():
    c = _conn()
    c.execute("""CREATE TABLE IF NOT EXISTS app_icons (
        app_name TEXT PRIMARY KEY,
        icon_path TEXT,
        fetched_at TEXT
    )""")
    c.commit()
    c.close()


def get_icon_path(app_name):
    c = _conn()
    r = c.execute("SELECT icon_path FROM app_icons WHERE app_name=?", (app_name,)).fetchone()
    c.close()
    return r[0] if r else None


def set_icon_path(app_name, path):
    c = _conn()
    c.execute("INSERT INTO app_icons(app_name, icon_path, fetched_at) VALUES(?,?,datetime('now','localtime'))"
              " ON CONFLICT(app_name) DO UPDATE SET icon_path=excluded.icon_path, fetched_at=excluded.fetched_at",
              (app_name, path))
    c.commit()
    c.close()
