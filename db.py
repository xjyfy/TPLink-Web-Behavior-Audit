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

-- 每小时预聚合汇总表：收到日志时增量累加，趋势查询读此表（O(小时数)），避免对 logs 大表全表聚合。
-- hourly_total: 每小时日志总数（ts 截取到小时）
CREATE TABLE IF NOT EXISTS hourly_total (
  hour TEXT PRIMARY KEY,
  total INTEGER NOT NULL DEFAULT 0
);
-- hourly_hosts: 每小时出现过的去重 host_ip（用于每小时在线终端数）
CREATE TABLE IF NOT EXISTS hourly_hosts (
  hour TEXT NOT NULL,
  host_ip TEXT NOT NULL,
  PRIMARY KEY (hour, host_ip)
);
CREATE INDEX IF NOT EXISTS idx_hh_hour ON hourly_hosts(hour);
-- hourly_app: 每小时应用聚合（热门应用 / 应用类别 / 网络协议）
CREATE TABLE IF NOT EXISTS hourly_app (
  hour TEXT NOT NULL,
  app_category TEXT NOT NULL DEFAULT '',
  app_name TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, app_category, app_name)
);
-- hourly_domain: 每小时域名聚合（热门网站）
CREATE TABLE IF NOT EXISTS hourly_domain (
  hour TEXT NOT NULL,
  domain TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, domain)
);
-- hourly_device: 每小时设备聚合（设备列表：数量 + 最近时间）
CREATE TABLE IF NOT EXISTS hourly_device (
  hour TEXT NOT NULL,
  device_ip TEXT NOT NULL,
  device_name TEXT,
  n INTEGER NOT NULL DEFAULT 0,
  last_ts TEXT,
  PRIMARY KEY (hour, device_ip)
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


def _agg_hour(rec):
    """返回日志 rec 对应的小时键与 host_ip（用于增量维护 hourly 汇总表）。"""
    ts = rec.get('ts')
    return (ts[:13] if ts else None), (rec.get('host_ip') or None)


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
    _agg_insert(c, rec)
    c.commit()
    c.close()


def _agg_insert(c, rec):
    """单条日志增量维护全部 hourly 预聚合表。"""
    hour = rec.get('ts')[:13] if rec.get('ts') else None
    if not hour:
        return
    c.execute("INSERT INTO hourly_total(hour,total) VALUES(?,1) "
              "ON CONFLICT(hour) DO UPDATE SET total=total+1", (hour,))
    if rec.get('host_ip'):
        c.execute("INSERT OR IGNORE INTO hourly_hosts(hour,host_ip) VALUES(?,?)", (hour, rec.get('host_ip')))
    et = rec.get('event_type')
    if et == 'app' and rec.get('app_name'):
        c.execute("INSERT INTO hourly_app(hour,app_category,app_name,n) VALUES(?,?,?,1) "
                  "ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=n+1",
                  (hour, rec.get('app_category') or '', rec.get('app_name')))
    if et in ('web', 'url') and rec.get('domain'):
        c.execute("INSERT INTO hourly_domain(hour,domain,n) VALUES(?,?,1) "
                  "ON CONFLICT(hour,domain) DO UPDATE SET n=n+1", (hour, rec.get('domain')))
    if rec.get('device_ip'):
        c.execute("INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts) VALUES(?,?,?,1,?) "
                  "ON CONFLICT(hour,device_ip) DO UPDATE SET n=n+1, device_name=excluded.device_name, last_ts=excluded.last_ts",
                  (hour, rec.get('device_ip'), rec.get('device_name') or '', rec.get('ts')))


def insert_many(rows):
    c = _conn()
    c.executemany("""INSERT INTO logs
        (ts, device_name, device_ip, module, level, raw, usergroup, host_ip,
         mac, assigned_ip, event_type, web_group, url, domain,
         app_category, app_name, dns_query)
        VALUES (:ts,:device_name,:device_ip,:module,:level,:raw,:usergroup,:host_ip,
                :mac,:assigned_ip,:event_type,:web_group,:url,:domain,
                :app_category,:app_name,:dns_query)""", rows)
    _agg_insert_many(c, rows)
    c.commit()
    c.close()


def _agg_insert_many(c, rows):
    """批量增量维护全部 hourly 预聚合表。"""
    total_map = {}
    host_set = set()
    app_map = {}
    domain_map = {}
    device_map = {}
    for r in rows:
        ts = r.get('ts')
        hour = ts[:13] if ts else None
        if not hour:
            continue
        total_map[hour] = total_map.get(hour, 0) + 1
        if r.get('host_ip'):
            host_set.add((hour, r.get('host_ip')))
        et = r.get('event_type')
        if et == 'app' and r.get('app_name'):
            key = (hour, r.get('app_category') or '', r.get('app_name'))
            app_map[key] = app_map.get(key, 0) + 1
        if et in ('web', 'url') and r.get('domain'):
            key = (hour, r.get('domain'))
            domain_map[key] = domain_map.get(key, 0) + 1
        if r.get('device_ip'):
            key = (hour, r.get('device_ip'))
            cur = device_map.get(key)
            if cur is None:
                device_map[key] = {'name': r.get('device_name') or '', 'ts': ts, 'cnt': 1}
            else:
                if ts > (cur['ts'] or ''):
                    cur['name'] = r.get('device_name') or ''
                    cur['ts'] = ts
                cur['cnt'] += 1
    for hour, n in total_map.items():
        c.execute("INSERT INTO hourly_total(hour,total) VALUES(?,?) "
                  "ON CONFLICT(hour) DO UPDATE SET total=total+?", (hour, n, n))
    if host_set:
        c.executemany("INSERT OR IGNORE INTO hourly_hosts(hour,host_ip) VALUES(?,?)", list(host_set))
    for (hour, cat, name), n in app_map.items():
        c.execute("INSERT INTO hourly_app(hour,app_category,app_name,n) VALUES(?,?,?,?) "
                  "ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=n+?", (hour, cat, name, n, n))
    for (hour, domain), n in domain_map.items():
        c.execute("INSERT INTO hourly_domain(hour,domain,n) VALUES(?,?,?) "
                  "ON CONFLICT(hour,domain) DO UPDATE SET n=n+?", (hour, domain, n, n))
    for (hour, ip), info in device_map.items():
        c.execute("INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(hour,device_ip) DO UPDATE SET n=n+?, device_name=excluded.device_name, last_ts=excluded.last_ts",
                  (hour, ip, info['name'], info['cnt'], info['ts'], info['cnt']))


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


def _hour_range(hours):
    """返回最近 hours 小时窗口的整点起点 hour 键（'%Y-%m-%d %H'）。"""
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = (now - timedelta(hours=hours - 1)).strftime('%Y-%m-%d %H')
    return now, start


def trend(hours=24):
    """日志量趋势：读 hourly 汇总表（O(hours)），不再扫描 logs 大表。"""
    c = _conn()
    now, start = _hour_range(hours)
    rows = c.execute("""SELECT hour hr, total n FROM hourly_total
        WHERE hour >= ? ORDER BY hour DESC LIMIT ?""", (start, hours)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    for i in range(hours - 1, -1, -1):
        hr = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
    return out


def online_trend(hours=24):
    """每小时在线终端数（去重 host_ip）：读 hourly_hosts 汇总表（O(hours)）。"""
    c = _conn()
    now, start = _hour_range(hours)
    rows = c.execute("""SELECT hour hr, COUNT(*) n FROM hourly_hosts
        WHERE hour >= ? GROUP BY hour ORDER BY hour DESC""", (start,)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    for i in range(hours - 1, -1, -1):
        hr = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
    return out


def _recalc_hour(c, hour):
    """从事务连接 c 从 logs 重算某小时的 total / 去重 host / app / domain / device（清理/回填后保持一致）。"""
    lo = hour + ':00:00'
    hi = hour + ':59:59'
    c.execute("DELETE FROM hourly_total WHERE hour=?", (hour,))
    r = c.execute("SELECT COUNT(*) n FROM logs WHERE ts>=? AND ts<=?", (lo, hi)).fetchone()
    if r and r['n']:
        c.execute("INSERT INTO hourly_total(hour,total) VALUES(?,?)", (hour, r['n']))
    c.execute("DELETE FROM hourly_hosts WHERE hour=?", (hour,))
    c.execute("""INSERT OR IGNORE INTO hourly_hosts(hour,host_ip)
        SELECT substr(ts,1,13), host_ip FROM logs WHERE ts>=? AND ts<=? AND host_ip IS NOT NULL""", (lo, hi))
    c.execute("DELETE FROM hourly_app WHERE hour=?", (hour,))
    c.execute("""INSERT INTO hourly_app(hour,app_category,app_name,n)
        SELECT substr(ts,1,13), COALESCE(app_category,''), app_name, COUNT(*)
        FROM logs WHERE ts>=? AND ts<=? AND event_type='app' AND app_name IS NOT NULL AND app_name!=''
        GROUP BY 1,2,3""", (lo, hi))
    c.execute("DELETE FROM hourly_domain WHERE hour=?", (hour,))
    c.execute("""INSERT INTO hourly_domain(hour,domain,n)
        SELECT substr(ts,1,13), domain, COUNT(*)
        FROM logs WHERE ts>=? AND ts<=? AND event_type IN ('web','url') AND domain IS NOT NULL AND domain!=''
        GROUP BY 1,2""", (lo, hi))
    c.execute("DELETE FROM hourly_device WHERE hour=?", (hour,))
    c.execute("""INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts)
        SELECT substr(ts,1,13), device_ip, device_name, COUNT(*), MAX(ts)
        FROM logs WHERE ts>=? AND ts<=? AND device_ip IS NOT NULL AND device_ip!=''
        GROUP BY 1,2""", (lo, hi))


def backfill_hourly():
    """服务启动时后台执行一次：用 logs 全量回填 hourly 汇总表（幂等、加写锁保证与增量不冲突）。
    只回填缺失小时（INSERT OR IGNORE / ON CONFLICT 覆盖），已有小时保留增量结果。"""
    try:
        c = _conn()
        c.execute("BEGIN IMMEDIATE")  # 写锁，避免与 insert_log 增量并发产生漏算/重复
        try:
            c.execute("""INSERT INTO hourly_total(hour,total)
                SELECT substr(ts,1,13) hour, COUNT(*) n FROM logs GROUP BY hour
                ON CONFLICT(hour) DO UPDATE SET total=excluded.total""")
            c.execute("""INSERT OR IGNORE INTO hourly_hosts(hour,host_ip)
                SELECT substr(ts,1,13), host_ip FROM logs WHERE host_ip IS NOT NULL""")
            c.execute("""INSERT INTO hourly_app(hour,app_category,app_name,n)
                SELECT substr(ts,1,13), COALESCE(app_category,''), app_name, COUNT(*)
                FROM logs WHERE event_type='app' AND app_name IS NOT NULL AND app_name!=''
                GROUP BY 1,2,3
                ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=excluded.n""")
            c.execute("""INSERT INTO hourly_domain(hour,domain,n)
                SELECT substr(ts,1,13), domain, COUNT(*)
                FROM logs WHERE event_type IN ('web','url') AND domain IS NOT NULL AND domain!=''
                GROUP BY 1,2
                ON CONFLICT(hour,domain) DO UPDATE SET n=excluded.n""")
            c.execute("""INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts)
                SELECT substr(ts,1,13), device_ip, device_name, COUNT(*), MAX(ts)
                FROM logs WHERE device_ip IS NOT NULL AND device_ip!=''
                GROUP BY 1,2
                ON CONFLICT(hour,device_ip) DO UPDATE SET n=excluded.n, device_name=excluded.device_name, last_ts=excluded.last_ts""")
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
    except Exception as e:
        print('[hourly-backfill] FAIL', e)


def _cond(w, extra):
    return (w + " AND " + extra) if w else ("WHERE " + extra)


def _hour_where(start, end):
    """把 start/end（'%Y-%m-%d %H:%M:%S'）转成预聚合表的小时范围 WHERE。"""
    where, p = [], []
    if start:
        where.append("hour >= ?"); p.append(start[:13])
    if end:
        where.append("hour <= ?"); p.append(end[:13])
    return ("WHERE " + " AND ".join(where)) if where else "", p


def top_hosts(limit=10, start=None, end=None):
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT host_ip k, COUNT(*) n FROM logs
        {_cond(w, "host_ip IS NOT NULL")} GROUP BY host_ip ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def top_domains(limit=10, start=None, end=None):
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT domain k, SUM(n) n FROM hourly_domain
        {w} GROUP BY domain ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def app_categories(start=None, end=None):
    """应用类别分布，排除'网络基础协议'（单独走协议TOP）。读 hourly_app。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '' AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC LIMIT 10""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def app_categories_all(start=None, end=None):
    """应用类别全量（不分页）。读 hourly_app。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '' AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def apps_by_category(category, start=None, end=None, limit=200):
    """指定应用类别下的具体应用（app_name）计数，用于类别完整列表页展开明细。读 hourly_app。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category=? AND app_name != ''")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [category, limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def top_apps(limit=10, start=None, end=None):
    """应用TOP，排除"网络基础协议"类别（HTTP/HTTPS/NTP/DNS 等，单独走协议TOP）。
    读 hourly_app，排除该类别 + http/https 名兜底。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '网络基础协议' AND lower(app_name) NOT IN ('http','https')")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def protocol_top(start=None, end=None):
    """网络协议TOP：仅日志里有明确协议名的（网络基础协议下的 app_name，如 HTTP/HTTPS/NTP）。
    域名类访问不并入，统一在热门网站图表展示。读 hourly_app。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""
        SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category='网络基础协议' AND app_name != ''")}
        GROUP BY app_name
        ORDER BY n DESC LIMIT 10""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def protocol_top_all(start=None, end=None):
    """网络协议全量（不分页）。读 hourly_app。"""
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""
        SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category='网络基础协议' AND app_name != ''")}
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
    # 同步 hourly 汇总表：删除受影响小时并重算（保证与 logs 一致）
    s_h, e_h = start[:13], end[:13]
    cur_h = s_h
    while cur_h <= e_h:
        _recalc_hour(c, cur_h)
        cur_h = (datetime.strptime(cur_h, '%Y-%m-%d %H') + timedelta(hours=1)).strftime('%Y-%m-%d %H')
    c.commit()
    c.close()
    return n


def prune(days):
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    c = _conn()
    cur = c.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
    n = cur.rowcount
    # 同步 hourly 汇总表：删除 cutoff 整点之前的所有小时，cutoff 所在小时重算（可能部分删除）
    cutoff_hour = cutoff[:13]
    c.execute("DELETE FROM hourly_total WHERE hour < ?", (cutoff_hour,))
    c.execute("DELETE FROM hourly_hosts WHERE hour < ?", (cutoff_hour,))
    _recalc_hour(c, cutoff_hour)
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


def list_hosts_page(keyword=None, page=1, size=20):
    """终端列表分页查询 + 统计。
    返回 {total(当前筛选匹配数), online_total(最近1小时在线终端数),
          all_total(终端总数), page, size, rows(带 online 标记)}。
    online 判定：logs 中该 IP 最近 1 小时有记录即视为在线。"""
    cutoff = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    w, p = "", []
    if keyword:
        w = "WHERE mac LIKE ? OR ip LIKE ? OR note LIKE ? OR hostname LIKE ?"
        k = '%' + keyword + '%'
        p = [k, k, k, k]
    c = _conn()
    all_total = c.execute("SELECT COUNT(*) n FROM hosts").fetchone()['n']
    online_total = c.execute(
        "SELECT COUNT(DISTINCT host_ip) n FROM logs WHERE ts>=? AND host_ip IS NOT NULL",
        (cutoff,)).fetchone()['n']
    total = c.execute(f"SELECT COUNT(*) n FROM hosts {w}", p).fetchone()['n']
    rows = c.execute(f"SELECT * FROM hosts {w} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                     p + [size, (page - 1) * size]).fetchall()
    # 批量判断当前页各 IP 是否在线（避免逐行查询）
    ips = [r['ip'] for r in rows if r['ip']]
    online_ips = set()
    if ips:
        ph = ','.join('?' * len(ips))
        for r in c.execute(
                f"SELECT DISTINCT host_ip FROM logs WHERE ts>=? AND host_ip IN ({ph})",
                [cutoff] + ips).fetchall():
            online_ips.add(r['host_ip'])
    out = []
    for r in rows:
        d = dict(r)
        d['online'] = (d.get('ip') or '') in online_ips
        out.append(d)
    c.close()
    return {'total': total, 'online_total': online_total, 'all_total': all_total,
            'page': page, 'size': size, 'rows': out}


def host_note_map_by_ip():
    """返回 {ip: note}，用于日志列表里按 IP 补备注。"""
    c = _conn()
    rows = c.execute("SELECT ip, note FROM hosts WHERE note IS NOT NULL AND note != ''").fetchall()
    c.close()
    return {r['ip']: r['note'] for r in rows}


# ---------- 数据来源设备 ----------
def list_devices():
    """从 hourly_device 预聚合表聚合出所有上报设备（数量+最近时间），LEFT JOIN devices 取自定义名称。"""
    c = _conn()
    rows = c.execute("""
        SELECT h.device_ip,
               (SELECT device_name FROM hourly_device h2 WHERE h2.device_ip=h.device_ip
                 ORDER BY hour DESC LIMIT 1) device_name,
               SUM(h.n) n,
               (SELECT last_ts FROM hourly_device h3 WHERE h3.device_ip=h.device_ip
                 ORDER BY hour DESC LIMIT 1) last_seen,
               COALESCE(d.custom_name, '') custom_name
        FROM hourly_device h LEFT JOIN devices d ON h.device_ip = d.device_ip
        WHERE h.device_ip IS NOT NULL AND h.device_ip != ''
        GROUP BY h.device_ip
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
