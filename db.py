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

CREATE TABLE IF NOT EXISTS hourly_total (
  hour TEXT PRIMARY KEY,
  total INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hourly_hosts (
  hour TEXT NOT NULL,
  host_ip TEXT NOT NULL,
  PRIMARY KEY (hour, host_ip)
);
CREATE INDEX IF NOT EXISTS idx_hh_hour ON hourly_hosts(hour);
CREATE TABLE IF NOT EXISTS hourly_app (
  hour TEXT NOT NULL,
  app_category TEXT NOT NULL DEFAULT '',
  app_name TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, app_category, app_name)
);
CREATE TABLE IF NOT EXISTS hourly_domain (
  hour TEXT NOT NULL,
  domain TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, domain)
);
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
    try:
        c.execute("ALTER TABLE hosts ADD COLUMN hostname TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
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
    ts = rec.get('ts')
    return (ts[:13] if ts else None), (rec.get('host_ip') or None)


def insert_log(rec):
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
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    start = (now - timedelta(hours=hours - 1)).strftime('%Y-%m-%d %H')
    return now, start


def trend(hours=24):
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
    try:
        c = _conn()
        c.execute("BEGIN IMMEDIATE")
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
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '' AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC LIMIT 10""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def app_categories_all(start=None, end=None):
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_category k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '' AND app_category != '网络基础协议'")}
        GROUP BY app_category ORDER BY n DESC""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def apps_by_category(category, start=None, end=None, limit=200):
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category=? AND app_name != ''")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [category, limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def apps_by_category_devices(category, start=None, end=None):
    """指定应用类别下，每个具体应用在时间段内使用的去重终端设备数。
    以 host_ip（真实终端）统计，排除上报设备自身（host_ip != device_ip，即路由器）。
    返回 {app_name: device_count}。直接查 logs。"""
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, COUNT(DISTINCT host_ip) devices
        FROM logs
        {_cond(w, "app_category=? AND app_name != '' AND host_ip IS NOT NULL AND host_ip != '' AND host_ip != device_ip")}
        GROUP BY app_name""", p + [category]).fetchall()
    c.close()
    return {r['k']: r['devices'] for r in rows}


def app_devices(app_name, start=None, end=None, page=1, size=20):
    """指定应用在时间段内使用的终端设备分页列表（去重 host_ip，排除上报设备自身）。
    返回 {total, page, size, rows:[{ip, mac, note, n}]}：IP、MAC(hosts表反查)、备注、使用次数。"""
    w, p = _range_where(start, end)
    cond = _cond(w, "app_name=? AND host_ip IS NOT NULL AND host_ip != '' AND host_ip != device_ip")
    c = _conn()
    total = c.execute(
        "SELECT COUNT(DISTINCT host_ip) n FROM logs " + cond,
        p + [app_name]).fetchone()['n']
    rows = c.execute("""SELECT host_ip ip, COUNT(*) n,
        (SELECT mac FROM hosts h WHERE h.ip = logs.host_ip LIMIT 1) mac,
        (SELECT note FROM hosts h WHERE h.ip = logs.host_ip LIMIT 1) note
        FROM logs """ + cond + " GROUP BY host_ip ORDER BY n DESC LIMIT ? OFFSET ?",
        p + [app_name, size, (page - 1) * size]).fetchall()
    c.close()
    return {'total': total, 'page': page, 'size': size, 'rows': [dict(r) for r in rows]}


def top_apps(limit=10, start=None, end=None):
    w, p = _hour_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, SUM(n) n FROM hourly_app
        {_cond(w, "app_category != '网络基础协议' AND lower(app_name) NOT IN ('http','https')")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def protocol_top(start=None, end=None):
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
    hostname = _resolve_hostname(ip)
    c = _conn()
    row = c.execute("SELECT mac, ip FROM hosts WHERE mac=?", (mac,)).fetchone()
    if row:
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
    返回 {total(当前筛选匹配数), online_total(最近在线终端数),
          all_total(终端总数), page, size, rows(带 online 标记)}。
    online 判定改用 hourly_hosts 预聚合表（最近2个整点小时内出现过 host_ip 即视为在线），
    避免对 logs 大表做时间过滤聚合，显著提速。"""
    cutoff_hour = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H')
    w, p = "", []
    if keyword:
        w = "WHERE mac LIKE ? OR ip LIKE ? OR note LIKE ? OR hostname LIKE ?"
        k = '%' + keyword + '%'
        p = [k, k, k, k]
    c = _conn()
    all_total = c.execute("SELECT COUNT(*) n FROM hosts").fetchone()['n']
    online_total = c.execute(
        "SELECT COUNT(DISTINCT host_ip) n FROM hourly_hosts WHERE hour >= ? AND host_ip IS NOT NULL",
        (cutoff_hour,)).fetchone()['n']
    total = c.execute(f"SELECT COUNT(*) n FROM hosts {w}", p).fetchone()['n']
    rows = c.execute(f"SELECT * FROM hosts {w} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                     p + [size, (page - 1) * size]).fetchall()
    ips = [r['ip'] for r in rows if r['ip']]
    online_ips = set()
    if ips:
        ph = ','.join('?' * len(ips))
        for r in c.execute(
                f"SELECT DISTINCT host_ip FROM hourly_hosts WHERE hour >= ? AND host_ip IN ({ph})",
                [cutoff_hour] + ips).fetchall():
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
    c = _conn()
    rows = c.execute("SELECT ip, note FROM hosts WHERE note IS NOT NULL AND note != ''").fetchall()
    c.close()
    return {r['ip']: r['note'] for r in rows}


# ---------- 数据来源设备 ----------
def list_devices():
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
    c.execute("CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)").fetchall()
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
