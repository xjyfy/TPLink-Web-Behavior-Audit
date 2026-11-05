# -*- coding: utf-8 -*-
"""SQLite 数据访问层。"""
import sqlite3
import hashlib
import os
import ipaddress
import threading
import time
from datetime import datetime, timedelta

import config

# 全局写锁：同进程内所有写操作（insert_log/cache_put/prune 等）串行执行，
# 消除 SQLite WAL 下多写者并发导致的 "database is locked"。
_WRITE_LOCK = threading.Lock()

# 日志清理分批大小：每批单独事务、批间释放写锁，避免长时间持锁阻塞入库
_PRUNE_BATCH = 20000

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
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  pw_hash TEXT,
  role TEXT DEFAULT 'admin',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  mac TEXT PRIMARY KEY,
  ip TEXT,
  hostname TEXT DEFAULT '',
  first_seen TEXT,
  last_seen TEXT,
  note TEXT DEFAULT ''
);
-- 按 IP 反查终端记录（入库时按 host_ip 批量刷新 last_seen 需要）
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);

CREATE TABLE IF NOT EXISTS devices (
  device_ip TEXT PRIMARY KEY,
  device_name TEXT,
  custom_name TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1
);

-- 排除 IP 列表：命中该列表的访问日志直接丢弃（不入库、不调网站名查询）
CREATE TABLE IF NOT EXISTS excluded_ips (
  ip TEXT PRIMARY KEY,
  note TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- 应用类别统计表：所有在日志中出现过的 app_category，收到新类别自动累加（供日志查询类别下拉等使用）
CREATE TABLE IF NOT EXISTS app_categories (
  name TEXT PRIMARY KEY,
  n INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT
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
-- 每10分钟预聚合表：供趋势图按10分钟一个点显示（避免扫描 logs 大表）。
-- min10_total: 每10分钟日志总数；min10_hosts: 每10分钟出现的去重 host_ip。
-- 桶键格式 'YYYY-MM-DD HH:MM'（分钟为10的倍数）。
CREATE TABLE IF NOT EXISTS min10_total (
  min10 TEXT PRIMARY KEY,
  total INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS min10_hosts (
  min10 TEXT NOT NULL,
  host_ip TEXT NOT NULL,
  PRIMARY KEY (min10, host_ip)
);
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
-- hourly_host_cat: 每小时各终端(host_ip)各应用类别的使用次数（供按终端统计的应用排行，如娱乐应用TOP）
CREATE TABLE IF NOT EXISTS hourly_host_cat (
  hour TEXT NOT NULL,
  host_ip TEXT NOT NULL,
  app_category TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, host_ip, app_category)
);
CREATE INDEX IF NOT EXISTS idx_hhc_cat ON hourly_host_cat(app_category, hour);

-- 域名/IP ↔ 网站名 长期数据表（对接 site-name-service，仅用于系统数据显示查询；域名/IP 唯一）
CREATE TABLE IF NOT EXISTS domain_site (
  domain TEXT PRIMARY KEY,
  site_name TEXT DEFAULT '',
  geo_tag TEXT DEFAULT '',
  updated_at TEXT
);
-- 域名/IP ↔ 网站名 24 小时缓存表（入库异步解析时先查此表，命中跳过；到期清理回写 domain_site）
CREATE TABLE IF NOT EXISTS domain_cache (
  domain TEXT PRIMARY KEY,
  site_name TEXT DEFAULT '',
  geo_tag TEXT DEFAULT '',
  expire_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dc_expire ON domain_cache(expire_at);
"""


def _conn():
    # timeout/busy_timeout 放宽到 30s：另有独立进程（site-name-service）共用本库，
    # 跨进程写竞争时等待锁而不是立刻抛 database is locked。
    c = sqlite3.connect(config.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=30000")
    # WAL 下 NORMAL 安全且省掉每次 commit 的 fsync，显著缩短写事务持锁时间
    c.execute("PRAGMA synchronous=NORMAL")
    # 连接级参数：提高自动 checkpoint 阈值（默认 1000 页），减少跨进程 checkpoint 争锁频率
    c.execute("PRAGMA wal_autocheckpoint=4000")
    return c


def init_db():
    c = _conn()
    # journal_mode 是数据库持久属性，在此设一次即可，不必每个连接重复设置（避免额外抢锁）
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(_SCHEMA)
    # 迁移：旧库加 hostname 列
    try:
        c.execute("ALTER TABLE hosts ADD COLUMN hostname TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    # 迁移：devices 加 enabled 列（默认启用）
    try:
        c.execute("ALTER TABLE devices ADD COLUMN enabled INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    # 迁移：admin 表由"单管理员(id=1, CHECK)"改为"多用户表(role 角色)"。
    # 旧表无 role 列 -> 重命名重建，原 id=1 管理员迁移为系统管理员。
    cols = [r['name'] for r in c.execute("PRAGMA table_info(admin)").fetchall()]
    if 'role' not in cols:
        c.execute("ALTER TABLE admin RENAME TO admin_old")
        c.execute("""CREATE TABLE admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            pw_hash TEXT,
            role TEXT DEFAULT 'admin',
            created_at TEXT
        )""")
        try:
            c.execute("INSERT INTO admin(id,username,pw_hash,role,created_at) "
                      "SELECT id,username,pw_hash,'system',datetime('now','localtime') FROM admin_old WHERE id=1")
        except sqlite3.OperationalError:
            c.execute("INSERT INTO admin(username,pw_hash,role,created_at) "
                      "SELECT username,pw_hash,'system',datetime('now','localtime') FROM admin_old WHERE id=1")
        c.execute("DROP TABLE admin_old")
    # 确保至少存在一个系统管理员（默认 id=1）
    sysrow = c.execute("SELECT id FROM admin WHERE id=1").fetchone()
    if not sysrow:
        other = c.execute("SELECT id FROM admin WHERE role='system' ORDER BY id LIMIT 1").fetchone()
        if other:
            # 已有系统管理员：把 id 校正为 1（迁移历史库可能没有 id=1）
            c.execute("UPDATE admin SET id=1 WHERE id=?", (other['id'],))
        else:
            c.execute("INSERT INTO admin(id, username, pw_hash, role, created_at) "
                      "VALUES (1,?,?,'system',datetime('now','localtime'))",
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
    """返回系统管理员（id=1）信息。"""
    c = _conn()
    r = c.execute("SELECT * FROM admin WHERE id=1").fetchone()
    c.close()
    return dict(r) if r else None


def get_admin_by_username(username):
    c = _conn()
    r = c.execute("SELECT * FROM admin WHERE username=?", (username,)).fetchone()
    c.close()
    return dict(r) if r else None


def get_admin_by_id(admin_id):
    c = _conn()
    r = c.execute("SELECT * FROM admin WHERE id=?", (admin_id,)).fetchone()
    c.close()
    return dict(r) if r else None


def list_admins():
    c = _conn()
    rows = c.execute("SELECT id, username, role, created_at FROM admin ORDER BY id").fetchall()
    c.close()
    return [dict(r) for r in rows]


def add_admin(username, pw, role='admin'):
    """新增管理员。返回 (ok, err)。"""
    if not username or not pw:
        return False, '用户名和密码不能为空'
    if role not in ('admin', 'audit'):
        return False, '角色不合法'
    c = _conn()
    try:
        c.execute("INSERT INTO admin(username, pw_hash, role, created_at) "
                  "VALUES (?,?,?,datetime('now','localtime'))",
                  (username, hash_pw(pw), role))
        c.commit()
        return True, ''
    except sqlite3.IntegrityError:
        return False, '用户名已存在'
    finally:
        c.close()


def update_admin(admin_id, username=None, pw=None, role=None):
    """修改管理员信息。返回 (ok, err)。"""
    if admin_id == 1:
        # 系统管理员不可改角色、不可删除；仅允许改用户名/密码
        role = 'system'
    sets, p = [], []
    if username is not None:
        sets.append("username=?"); p.append(username)
    if pw:
        sets.append("pw_hash=?"); p.append(hash_pw(pw))
    if role is not None:
        sets.append("role=?"); p.append(role)
    if not sets:
        return True, ''
    c = _conn()
    try:
        c.execute("UPDATE admin SET " + ",".join(sets) + " WHERE id=?", p + [admin_id])
        c.commit()
        return True, ''
    except sqlite3.IntegrityError:
        return False, '用户名已存在'
    finally:
        c.close()


def delete_admin(admin_id):
    """删除管理员。系统管理员(id=1)不可删除。返回 (ok, err)。"""
    if admin_id == 1:
        return False, '系统管理员不可删除'
    c = _conn()
    cur = c.execute("DELETE FROM admin WHERE id=?", (admin_id,))
    c.commit()
    c.close()
    return (cur.rowcount > 0), '' if cur.rowcount else '用户不存在'


def change_password(username, old_pw, new_pw):
    a = get_admin_by_username(username)
    if not a or not verify_pw(old_pw, a['pw_hash']):
        return False
    c = _conn()
    c.execute("UPDATE admin SET pw_hash=? WHERE username=?", (hash_pw(new_pw), username))
    c.commit()
    c.close()
    return True


def _agg_hour(rec):
    """返回日志 rec 对应的小时键与 host_ip（用于增量维护 hourly 汇总表）。"""
    ts = rec.get('ts')
    return (ts[:13] if ts else None), (rec.get('host_ip') or None)


def _min10_key(ts):
    """ts('YYYY-MM-DD HH:MM:SS') -> 'YYYY-MM-DD HH:MM'（10 分钟桶，分钟为 10 的倍数）。"""
    if not ts or len(ts) < 16:
        return None
    try:
        m = int(ts[14:16]) // 10 * 10
        return ts[:13] + ':' + str(m).zfill(2)
    except Exception:
        return None


# SQL 表达式：把 logs.ts 转成 10 分钟桶键（供 backfill 从大表回填 10 分钟聚合）
_MIN10_SQL = ("strftime('%Y-%m-%d %H', ts) || ':' || "
              "printf('%02d', (CAST(strftime('%M', ts) AS INTEGER) / 10) * 10)")


def insert_log(rec):
    """rec: dict with normalized fields + ts + device_name/ip/module/level/raw."""
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("""INSERT INTO logs
                (ts, device_name, device_ip, module, level, raw, usergroup, host_ip,
                 mac, assigned_ip, event_type, web_group, url, domain,
                 app_category, app_name, dns_query)
                VALUES (:ts,:device_name,:device_ip,:module,:level,:raw,:usergroup,:host_ip,
                        :mac,:assigned_ip,:event_type,:web_group,:url,:domain,
                        :app_category,:app_name,:dns_query)""", rec)
            _agg_insert(c, rec)
            c.commit()
        finally:
            c.close()


def _agg_insert(c, rec):
    """单条日志增量维护全部 hourly 预聚合表 + min10 预聚合表。"""
    hour = rec.get('ts')[:13] if rec.get('ts') else None
    if not hour:
        return
    c.execute("INSERT INTO hourly_total(hour,total) VALUES(?,1) "
              "ON CONFLICT(hour) DO UPDATE SET total=total+1", (hour,))
    if rec.get('host_ip'):
        c.execute("INSERT OR IGNORE INTO hourly_hosts(hour,host_ip) VALUES(?,?)", (hour, rec.get('host_ip')))
    # 10 分钟桶增量
    m10 = _min10_key(rec.get('ts'))
    if m10:
        c.execute("INSERT INTO min10_total(min10,total) VALUES(?,1) "
                  "ON CONFLICT(min10) DO UPDATE SET total=total+1", (m10,))
        if rec.get('host_ip'):
            c.execute("INSERT OR IGNORE INTO min10_hosts(min10,host_ip) VALUES(?,?)", (m10, rec.get('host_ip')))
    et = rec.get('event_type')
    if et == 'app' and rec.get('app_name'):
        c.execute("INSERT INTO hourly_app(hour,app_category,app_name,n) VALUES(?,?,?,1) "
                  "ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=n+1",
                  (hour, rec.get('app_category') or '', rec.get('app_name')))
        if rec.get('host_ip') and rec.get('app_category'):
            c.execute("INSERT INTO hourly_host_cat(hour,host_ip,app_category,n) VALUES(?,?,?,1) "
                      "ON CONFLICT(hour,host_ip,app_category) DO UPDATE SET n=n+1",
                      (hour, rec.get('host_ip'), rec.get('app_category')))
    if et in ('web', 'url') and rec.get('domain'):
        c.execute("INSERT INTO hourly_domain(hour,domain,n) VALUES(?,?,1) "
                  "ON CONFLICT(hour,domain) DO UPDATE SET n=n+1", (hour, rec.get('domain')))
    cat = rec.get('app_category')
    if cat:
        c.execute("INSERT INTO app_categories(name,n,first_seen,last_seen) VALUES(?,1,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET n=n+1, last_seen=excluded.last_seen",
                  (cat, rec.get('ts'), rec.get('ts')))
    if rec.get('device_ip'):
        c.execute("INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts) VALUES(?,?,?,1,?) "
                  "ON CONFLICT(hour,device_ip) DO UPDATE SET n=n+1, device_name=excluded.device_name, last_ts=excluded.last_ts",
                  (hour, rec.get('device_ip'), rec.get('device_name') or '', rec.get('ts')))
    # 终端最后在线时间：由日志活动维护（不再依赖 DHCP 上报）。
    # 仅更新 hosts 里已存在的 IP（UPDATE 无匹配即空操作），且只前进不后退。
    if rec.get('host_ip') and rec.get('ts'):
        c.execute("UPDATE hosts SET last_seen=? WHERE ip=? AND (last_seen IS NULL OR last_seen < ?)",
                  (rec.get('ts'), rec.get('host_ip'), rec.get('ts')))


def insert_many(rows):
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.executemany("""INSERT INTO logs
                (ts, device_name, device_ip, module, level, raw, usergroup, host_ip,
                 mac, assigned_ip, event_type, web_group, url, domain,
                 app_category, app_name, dns_query)
                VALUES (:ts,:device_name,:device_ip,:module,:level,:raw,:usergroup,:host_ip,
                        :mac,:assigned_ip,:event_type,:web_group,:url,:domain,
                        :app_category,:app_name,:dns_query)""", rows)
            _agg_insert_many(c, rows)
            c.commit()
        finally:
            c.close()


def _agg_insert_many(c, rows):
    """批量增量维护全部 hourly 预聚合表 + min10 预聚合表。"""
    total_map = {}
    host_set = set()
    host_last_map = {}
    m10_total_map = {}
    m10_host_set = set()
    app_map = {}
    host_cat_map = {}
    cat_map = {}
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
            hp = r.get('host_ip'); tsv = ts or ''
            if tsv > host_last_map.get(hp, ''):
                host_last_map[hp] = tsv
        m10 = _min10_key(ts)
        if m10:
            m10_total_map[m10] = m10_total_map.get(m10, 0) + 1
            if r.get('host_ip'):
                m10_host_set.add((m10, r.get('host_ip')))
        et = r.get('event_type')
        if et == 'app' and r.get('app_name'):
            key = (hour, r.get('app_category') or '', r.get('app_name'))
            app_map[key] = app_map.get(key, 0) + 1
        if et == 'app' and r.get('host_ip') and r.get('app_category'):
            key = (hour, r.get('host_ip'), r.get('app_category'))
            host_cat_map[key] = host_cat_map.get(key, 0) + 1
        if r.get('app_category'):
            cat_map.setdefault(r.get('app_category'), {'cnt': 0, 'first': ts, 'last': ts})
            ci = cat_map[r.get('app_category')]
            ci['cnt'] += 1
            if ts > (ci['last'] or ''):
                ci['last'] = ts
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
    for m10, n in m10_total_map.items():
        c.execute("INSERT INTO min10_total(min10,total) VALUES(?,?) "
                  "ON CONFLICT(min10) DO UPDATE SET total=total+?", (m10, n, n))
    if m10_host_set:
        c.executemany("INSERT OR IGNORE INTO min10_hosts(min10,host_ip) VALUES(?,?)", list(m10_host_set))
    for (hour, cat, name), n in app_map.items():
        c.execute("INSERT INTO hourly_app(hour,app_category,app_name,n) VALUES(?,?,?,?) "
                  "ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=n+?", (hour, cat, name, n, n))
    for (hour, ip, cat), n in host_cat_map.items():
        c.execute("INSERT INTO hourly_host_cat(hour,host_ip,app_category,n) VALUES(?,?,?,?) "
                  "ON CONFLICT(hour,host_ip,app_category) DO UPDATE SET n=n+?",
                  (hour, ip, cat, n, n))
    for (hour, domain), n in domain_map.items():
        c.execute("INSERT INTO hourly_domain(hour,domain,n) VALUES(?,?,?) "
                  "ON CONFLICT(hour,domain) DO UPDATE SET n=n+?", (hour, domain, n, n))
    for cat, ci in cat_map.items():
        c.execute("INSERT INTO app_categories(name,n,first_seen,last_seen) VALUES(?,?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET n=n+?, last_seen=excluded.last_seen",
                  (cat, ci['cnt'], ci['first'], ci['last'], ci['cnt']))
    for (hour, ip), info in device_map.items():
        c.execute("INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(hour,device_ip) DO UPDATE SET n=n+?, device_name=excluded.device_name, last_ts=excluded.last_ts",
                  (hour, ip, info['name'], info['cnt'], info['ts'], info['cnt']))
    # 终端最后在线时间：本批日志涉及的 IP 批量刷新（每批约 17 个 IP，成本可忽略）。
    # 只更新 hosts 已存在的 IP，且只前进不后退。
    if host_last_map:
        c.executemany("UPDATE hosts SET last_seen=? WHERE ip=? AND (last_seen IS NULL OR last_seen < ?)",
                      [(t, ip, t) for ip, t in host_last_map.items()])


def _build_logs_where(start=None, end=None, host_ip=None, event_type=None,
                      app_category=None, app_name=None, keyword=None):
    """构造日志查询/导出的 WHERE 与参数。app_category 可为逗号分隔字符串或列表（多选）。"""
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
        if isinstance(app_category, str):
            app_category = [x for x in app_category.split(',') if x]
        if app_category:
            ph = ','.join('?' * len(app_category))
            where.append(f"app_category IN ({ph})"); params += app_category
    if app_name:
        where.append("app_name = ?"); params.append(app_name)
    if keyword:
        where.append("(raw LIKE ? OR url LIKE ? OR domain LIKE ? OR app_name LIKE ? OR host_ip LIKE ?)")
        k = '%' + keyword + '%'
        params += [k, k, k, k, k]
    w = ("WHERE " + " AND ".join(where)) if where else ""
    return w, params


def query_logs(start=None, end=None, host_ip=None, event_type=None,
               app_category=None, app_name=None, keyword=None, page=1, size=50):
    w, params = _build_logs_where(start, end, host_ip, event_type,
                                  app_category, app_name, keyword)
    c = _conn()
    total = c.execute(f"SELECT COUNT(*) n FROM logs {w}", params).fetchone()['n']
    rows = c.execute(f"""SELECT * FROM logs {w} ORDER BY id DESC LIMIT ? OFFSET ?""",
                    params + [size, (page - 1) * size]).fetchall()
    c.close()
    return total, [dict(r) for r in rows]


def query_logs_all(start=None, end=None, host_ip=None, event_type=None,
                   app_category=None, app_name=None, keyword=None):
    """返回满足查询条件的所有日志（不分页，供日志查询导出 CSV）。"""
    w, params = _build_logs_where(start, end, host_ip, event_type,
                                  app_category, app_name, keyword)
    c = _conn()
    rows = c.execute(f"""SELECT ts, device_name, module, level, host_ip, event_type,
        web_group, domain, url, app_category, app_name, raw
        FROM logs {w} ORDER BY id ASC""", params).fetchall()
    c.close()
    return [dict(r) for r in rows]


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


def _min10_now():
    """当前时间的 10 分钟桶起点 datetime（分钟截为 10 的倍数）。"""
    now = datetime.now()
    return now.replace(minute=(now.minute // 10) * 10, second=0, microsecond=0)


def trend(hours=24):
    """日志量趋势：读 min10 汇总表，每 10 分钟一个点（hours 小时 = hours*6 个点）。"""
    c = _conn()
    cur_last = _min10_now()
    total_points = hours * 6
    start_dt = cur_last - timedelta(minutes=10 * (total_points - 1))
    start = start_dt.strftime('%Y-%m-%d %H:%M')
    rows = c.execute("SELECT min10 hr, total n FROM min10_total "
                     "WHERE min10 >= ? ORDER BY min10", (start,)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    cur = start_dt
    for _ in range(total_points):
        hr = cur.strftime('%Y-%m-%d %H:%M')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
        cur += timedelta(minutes=10)
    return out


def online_trend(hours=24):
    """每 10 分钟在线终端数（去重 host_ip）：读 min10_hosts 汇总表。"""
    c = _conn()
    cur_last = _min10_now()
    total_points = hours * 6
    start_dt = cur_last - timedelta(minutes=10 * (total_points - 1))
    start = start_dt.strftime('%Y-%m-%d %H:%M')
    rows = c.execute("SELECT min10 hr, COUNT(*) n FROM min10_hosts "
                     "WHERE min10 >= ? GROUP BY min10 ORDER BY min10", (start,)).fetchall()
    c.close()
    d = {r['hr']: r['n'] for r in rows}
    out = []
    cur = start_dt
    for _ in range(total_points):
        hr = cur.strftime('%Y-%m-%d %H:%M')
        out.append({'hr': hr, 'n': d.get(hr, 0)})
        cur += timedelta(minutes=10)
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
    c.execute("DELETE FROM hourly_host_cat WHERE hour=?", (hour,))
    c.execute("""INSERT INTO hourly_host_cat(hour,host_ip,app_category,n)
        SELECT substr(ts,1,13), host_ip, app_category, COUNT(*)
        FROM logs WHERE ts>=? AND ts<=? AND event_type='app' AND host_ip IS NOT NULL AND host_ip!=''
          AND app_category IS NOT NULL AND app_category!=''
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


def _recalc_min10(c, min10):
    """从事务连接 c 从 logs 重算某 10 分钟桶的 total / 去重 host（清理后保持一致）。"""
    lo = min10 + ':00'
    hi = min10 + ':59'
    c.execute("DELETE FROM min10_total WHERE min10=?", (min10,))
    r = c.execute("SELECT COUNT(*) n FROM logs WHERE ts>=? AND ts<=?", (lo, hi)).fetchone()
    if r and r['n']:
        c.execute("INSERT INTO min10_total(min10,total) VALUES(?,?)", (min10, r['n']))
    c.execute("DELETE FROM min10_hosts WHERE min10=?", (min10,))
    c.execute("""INSERT OR IGNORE INTO min10_hosts(min10,host_ip)
        SELECT ?, host_ip FROM logs WHERE ts>=? AND ts<=? AND host_ip IS NOT NULL AND host_ip!=''
        GROUP BY host_ip""", (min10, lo, hi))


def backfill_hourly():
    """服务启动时后台执行一次：用 logs 回填 hourly/min10 汇总表（幂等）。
    只回填最近 72 小时（增量已在维护，重启只需补最近窗口）。
    每条聚合语句各自一个短事务、语句之间释放写锁，避免启动期单一大事务长时间占用写锁，
    导致 syslog 入库线程 database is locked。"""
    win = "ts >= datetime('now','localtime','-72 hours')"
    sqls = [
        f"""INSERT INTO hourly_total(hour,total)
            SELECT substr(ts,1,13) hour, COUNT(*) n FROM logs
            WHERE {win} GROUP BY hour
            ON CONFLICT(hour) DO UPDATE SET total=excluded.total""",
        f"""INSERT OR IGNORE INTO hourly_hosts(hour,host_ip)
            SELECT substr(ts,1,13), host_ip FROM logs
            WHERE host_ip IS NOT NULL AND {win}""",
        f"""INSERT INTO hourly_app(hour,app_category,app_name,n)
            SELECT substr(ts,1,13), COALESCE(app_category,''), app_name, COUNT(*)
            FROM logs WHERE event_type='app' AND app_name IS NOT NULL AND app_name!=''
              AND {win}
            GROUP BY 1,2,3
            ON CONFLICT(hour,app_category,app_name) DO UPDATE SET n=excluded.n""",
        f"""INSERT INTO hourly_host_cat(hour,host_ip,app_category,n)
            SELECT substr(ts,1,13), host_ip, app_category, COUNT(*)
            FROM logs WHERE event_type='app' AND host_ip IS NOT NULL AND host_ip!=''
              AND app_category IS NOT NULL AND app_category!=''
              AND {win}
            GROUP BY 1,2,3
            ON CONFLICT(hour,host_ip,app_category) DO UPDATE SET n=excluded.n""",
        f"""INSERT INTO hourly_domain(hour,domain,n)
            SELECT substr(ts,1,13), domain, COUNT(*)
            FROM logs WHERE event_type IN ('web','url') AND domain IS NOT NULL AND domain!=''
              AND {win}
            GROUP BY 1,2
            ON CONFLICT(hour,domain) DO UPDATE SET n=excluded.n""",
        f"""INSERT INTO hourly_device(hour,device_ip,device_name,n,last_ts)
            SELECT substr(ts,1,13), device_ip, device_name, COUNT(*), MAX(ts)
            FROM logs WHERE device_ip IS NOT NULL AND device_ip!=''
              AND {win}
            GROUP BY 1,2
            ON CONFLICT(hour,device_ip) DO UPDATE SET n=excluded.n, device_name=excluded.device_name, last_ts=excluded.last_ts""",
        f"""INSERT INTO app_categories(name,n,first_seen,last_seen)
            SELECT app_category, COUNT(*), MIN(ts), MAX(ts) FROM logs
            WHERE app_category IS NOT NULL AND app_category != ''
              AND {win}
            GROUP BY app_category
            ON CONFLICT(name) DO UPDATE SET n=excluded.n, first_seen=excluded.first_seen, last_seen=excluded.last_seen""",
        f"INSERT INTO min10_total(min10,total) SELECT {_MIN10_SQL}, COUNT(*) FROM logs "
        f"WHERE {win} GROUP BY 1 ON CONFLICT(min10) DO UPDATE SET total=excluded.total",
        f"INSERT OR IGNORE INTO min10_hosts(min10,host_ip) SELECT {_MIN10_SQL}, host_ip FROM logs "
        f"WHERE host_ip IS NOT NULL AND host_ip != '' AND {win} GROUP BY 1,2",
    ]
    try:
        for sql in sqls:
            with _WRITE_LOCK:
                c = _conn()
                try:
                    c.execute(sql)
                    c.commit()
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


# 娱乐应用：网络购物 / 网络音乐 / 视频直播（按终端 IP 统计使用次数）
ENTERTAINMENT_CATEGORIES = ('网络购物', '网络音乐', '视频直播')


def _entertainment_where(start=None, end=None):
    """娱乐应用终端统计的 WHERE 与参数（hourly_host_cat 上按小时范围 + 类别 IN 过滤）。"""
    w, p = _hour_where(start, end)
    ph = ','.join('?' * len(ENTERTAINMENT_CATEGORIES))
    return _cond(w, f"app_category IN ({ph}) AND host_ip IS NOT NULL AND host_ip != ''"), \
        p + list(ENTERTAINMENT_CATEGORIES)


def entertainment_hosts(limit=10, start=None, end=None):
    """娱乐应用使用次数最多的终端 IP 排行（网络购物/网络音乐/视频直播）。读 hourly_host_cat。"""
    w, p = _entertainment_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT host_ip k, SUM(n) n FROM hourly_host_cat
        {w} GROUP BY host_ip ORDER BY n DESC LIMIT ?""", p + [limit]).fetchall()
    c.close()
    return [dict(r) for r in rows]


def entertainment_hosts_all(start=None, end=None):
    """娱乐应用终端 IP 全量排行（不分页，供完整列表页）。读 hourly_host_cat。"""
    w, p = _entertainment_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT host_ip k, SUM(n) n FROM hourly_host_cat
        {w} GROUP BY host_ip ORDER BY n DESC""", p).fetchall()
    c.close()
    return [dict(r) for r in rows]


def host_entertainment_apps(host_ip, start=None, end=None):
    """指定终端在娱乐应用类别（网络购物/网络音乐/视频直播）下使用的具体应用及次数。
    读 logs（按 host_ip + 时间范围 + 类别过滤，命中 idx_ts_host/idx_host），供完整列表页点击 IP 展开明细。"""
    if not host_ip:
        return []
    # 与 hourly 排名的整点窗口保持一致：start/end 截到整点闭区间，
    # 避免排名含整点时段数据而展开从 start 完整时间起导致的错位/为空
    lo = (start[:13] + ':00:00') if start else None
    hi = (end[:13] + ':59:59') if end else None
    w, p = _range_where(lo, hi)
    ph = ','.join('?' * len(ENTERTAINMENT_CATEGORIES))
    cond = (f"host_ip=? AND event_type='app' AND app_category IN ({ph}) "
            f"AND app_name IS NOT NULL AND app_name != ''")
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, app_category cat, COUNT(*) n FROM logs
        {_cond(w, cond)} GROUP BY app_name, app_category ORDER BY n DESC""",
                     p + [host_ip] + list(ENTERTAINMENT_CATEGORIES)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def list_categories():
    """应用类别统计表全量（供日志查询类别下拉）。按使用次数降序。"""
    c = _conn()
    rows = c.execute("SELECT name k, n FROM app_categories ORDER BY n DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def online_host_ips(hours=1):
    """最近 hours 小时内在线的去重 host_ip 集合（读 hourly_hosts 预聚合表）。"""
    cutoff_hour = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H')
    c = _conn()
    rows = c.execute("SELECT DISTINCT host_ip FROM hourly_hosts WHERE hour >= ? AND host_ip IS NOT NULL",
                     (cutoff_hour,)).fetchall()
    c.close()
    return {r['host_ip'] for r in rows}


def host_top_apps_domains(host_ip, start=None, end=None, limit=10):
    """指定终端使用最多的应用 与 网站（各 top10），供终端 IP 完整列表页点击展开。
    返回 {'apps':[{k,n}], 'domains':[{k,n}]}。"""
    out = {'apps': [], 'domains': []}
    if not host_ip:
        return out
    w, p = _range_where(start, end)
    c = _conn()
    rows = c.execute(f"""SELECT app_name k, COUNT(*) n FROM logs
        {_cond(w, "host_ip=? AND event_type='app' AND app_name IS NOT NULL AND app_name != ''")}
        GROUP BY app_name ORDER BY n DESC LIMIT ?""", p + [host_ip, limit]).fetchall()
    out['apps'] = [dict(r) for r in rows]
    rows = c.execute(f"""SELECT domain k, COUNT(*) n FROM logs
        {_cond(w, "host_ip=? AND event_type IN ('web','url') AND domain IS NOT NULL AND domain != ''")}
        GROUP BY domain ORDER BY n DESC LIMIT ?""", p + [host_ip, limit]).fetchall()
    out['domains'] = [dict(r) for r in rows]
    c.close()
    return out


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
    total = 0
    with _WRITE_LOCK:
        # 分批删除大表，避免单个大事务长时间持锁导致 syslog 入库 database is locked
        while True:
            c = _conn()
            try:
                cur = c.execute("DELETE FROM logs WHERE ts >= ? AND ts <= ? LIMIT 20000", (start, end))
                n = cur.rowcount
                c.commit()
            finally:
                c.close()
            total += n
            if n < 20000:
                break
        # 同步 hourly 汇总表：删除受影响小时并重算（保证与 logs 一致）
        c = _conn()
        try:
            s_h, e_h = start[:13], end[:13]
            cur_h = s_h
            while cur_h <= e_h:
                _recalc_hour(c, cur_h)
                cur_h = (datetime.strptime(cur_h, '%Y-%m-%d %H') + timedelta(hours=1)).strftime('%Y-%m-%d %H')
            # 同步 min10 汇总表：重算受影响 10 分钟桶
            s_m10 = _min10_key(start)
            e_m10 = _min10_key(end)
            cur_m = s_m10
            while cur_m <= e_m10:
                _recalc_min10(c, cur_m)
                cur_m = (datetime.strptime(cur_m, '%Y-%m-%d %H:%M') + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M')
            c.commit()
        finally:
            c.close()
    return total


def prune(days, max_rows=200000):
    """删除早于 days 天的日志及对应汇总桶。

    分批执行：每批一个独立事务并在批间释放写锁 + 短暂休眠，让入库线程插队，
    避免长时间独占写锁导致 syslog 入库 database is locked；
    单轮最多删除 max_rows 行，未删完的部分由下一轮（每小时）继续。
    """
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    total = 0
    # 分批删除大表：SQLite 标准版不支持 DELETE ... LIMIT，改用 rowid 子查询取前 N 行
    while True:
        with _WRITE_LOCK:
            c = _conn()
            try:
                cur = c.execute(
                    "DELETE FROM logs WHERE rowid IN "
                    "(SELECT rowid FROM logs WHERE ts < ? ORDER BY ts LIMIT ?)",
                    (cutoff, _PRUNE_BATCH))
                n = cur.rowcount
                c.commit()
            finally:
                c.close()
        total += n
        if n < _PRUNE_BATCH or total >= max_rows:
            break
        time.sleep(0.05)
    # 同步 hourly 汇总表：删除 cutoff 整点之前的所有小时，cutoff 所在小时重算（可能部分删除）
    with _WRITE_LOCK:
        c = _conn()
        try:
            cutoff_hour = cutoff[:13]
            c.execute("DELETE FROM hourly_total WHERE hour < ?", (cutoff_hour,))
            c.execute("DELETE FROM hourly_hosts WHERE hour < ?", (cutoff_hour,))
            c.execute("DELETE FROM hourly_host_cat WHERE hour < ?", (cutoff_hour,))
            _recalc_hour(c, cutoff_hour)
            # 同步 min10 汇总表：删除 cutoff 之前的 10 分钟桶，cutoff 所在桶重算
            cutoff_m10 = _min10_key(cutoff)
            c.execute("DELETE FROM min10_total WHERE min10 < ?", (cutoff_m10,))
            c.execute("DELETE FROM min10_hosts WHERE min10 < ?", (cutoff_m10,))
            if cutoff_m10:
                _recalc_min10(c, cutoff_m10)
            c.commit()
        finally:
            c.close()
    if total >= max_rows:
        print('[prune] 本轮删除 %d 行（达单轮上限），剩余留待下一轮' % total)
    return total


# ---------- 终端（MAC -> IP 动态映射 + 备注） ----------
def upsert_host(mac, ip, ts=None):
    """DHCP 事件：仅维护 MAC->IP 映射与首次出现时间（first_seen）。
    last_seen（最后在线时间）改由日志入库路径按 host_ip 批量维护，DHCP 不再写入，
    避免"只走 DHCP 才更新"导致静态 IP / 无 DHCP 上报的设备永远没有最后在线时间。"""
    if not mac:
        return
    ts = ts or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 反向解析主机名（DNS / NetBIOS），在写锁外完成，避免持锁阻塞
    hostname = _resolve_hostname(ip)
    with _WRITE_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT mac, ip FROM hosts WHERE mac=?", (mac,)).fetchone()
            if row:
                old = dict(row)
                new_hostname = hostname if old['ip'] != ip else None
                if new_hostname:
                    c.execute("UPDATE hosts SET ip=?, hostname=? WHERE mac=?", (ip, new_hostname, mac))
                else:
                    c.execute("UPDATE hosts SET ip=? WHERE mac=?", (ip, mac))
            else:
                c.execute("INSERT INTO hosts(mac, ip, hostname, first_seen, last_seen, note) VALUES (?,?,?,?,NULL,'')",
                          (mac, ip, hostname or '', ts))
            c.commit()
        finally:
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
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("UPDATE hosts SET note=? WHERE mac=?", (note, mac))
            c.commit()
        finally:
            c.close()


def list_hosts_page(keyword=None, page=1, size=20, offline_days=None):
    """终端列表分页查询 + 统计。
    返回 {total(当前筛选匹配数), online_total(最近在线终端数),
          all_total(终端总数), page, size, rows(带 online 标记)}。
    online 判定改用 hourly_hosts 预聚合表（最近2个整点小时内出现过 host_ip 即视为在线），
    避免对 logs 大表做时间过滤聚合，显著提速。
    offline_days: 只看长期离线终端（last_seen 早于 N 天前，或从未有在线记录）。"""
    # 最近1小时窗口覆盖当前及上一整点小时；取这两个整点小时内的活跃 host
    cutoff_hour = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H')
    conds, p = [], []
    if keyword:
        conds.append("(mac LIKE ? OR ip LIKE ? OR note LIKE ? OR hostname LIKE ?)")
        k = '%' + keyword + '%'
        p += [k, k, k, k]
    if offline_days:
        off_cutoff = (datetime.now() - timedelta(days=int(offline_days))).strftime('%Y-%m-%d %H:%M:%S')
        conds.append("(last_seen IS NULL OR last_seen < ?)")
        p.append(off_cutoff)
    w = ("WHERE " + " AND ".join(conds)) if conds else ""
    c = _conn()
    all_total = c.execute("SELECT COUNT(*) n FROM hosts").fetchone()['n']
    online_total = c.execute(
        "SELECT COUNT(DISTINCT host_ip) n FROM hourly_hosts WHERE hour >= ? AND host_ip IS NOT NULL",
        (cutoff_hour,)).fetchone()['n']
    total = c.execute(f"SELECT COUNT(*) n FROM hosts {w}", p).fetchone()['n']
    # 长期离线筛选时按“离线最久优先”排序：从未在线的排最前，其余按最后在线时间升序
    order = "ORDER BY (last_seen IS NULL) DESC, last_seen ASC" if offline_days else "ORDER BY last_seen DESC"
    rows = c.execute(f"SELECT * FROM hosts {w} {order} LIMIT ? OFFSET ?",
                     p + [size, (page - 1) * size]).fetchall()
    # 批量判断当前页各 IP 是否在线（读 hourly_hosts，避免逐行查 logs）
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
    """返回 {ip: note}，用于日志列表里按 IP 补备注。"""
    c = _conn()
    rows = c.execute("SELECT ip, note FROM hosts WHERE note IS NOT NULL AND note != ''").fetchall()
    c.close()
    return {r['ip']: r['note'] for r in rows}


# ---------- 数据来源设备 ----------
def list_devices():
    """从 hourly_device 预聚合表聚合出所有上报设备（数量+最近时间），LEFT JOIN devices 取自定义名称与启用状态。"""
    c = _conn()
    rows = c.execute("""
        SELECT h.device_ip,
               (SELECT device_name FROM hourly_device h2 WHERE h2.device_ip=h.device_ip
                 ORDER BY hour DESC LIMIT 1) device_name,
               SUM(h.n) n,
               (SELECT last_ts FROM hourly_device h3 WHERE h3.device_ip=h.device_ip
                 ORDER BY hour DESC LIMIT 1) last_seen,
               COALESCE(d.custom_name, '') custom_name,
               COALESCE(d.enabled, 1) enabled
        FROM hourly_device h LEFT JOIN devices d ON h.device_ip = d.device_ip
        WHERE h.device_ip IS NOT NULL AND h.device_ip != ''
        GROUP BY h.device_ip
        ORDER BY n DESC""").fetchall()
    c.close()
    return [dict(r) for r in rows]


def set_device_name(device_ip, custom_name):
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("""INSERT INTO devices(device_ip, custom_name) VALUES(?,?)
                ON CONFLICT(device_ip) DO UPDATE SET custom_name=excluded.custom_name""",
                (device_ip, custom_name))
            c.commit()
        finally:
            c.close()


def set_device_enabled(device_ip, enabled):
    """启用(1)或禁用(0)某数据来源设备。返回 (ok, err)。"""
    with _WRITE_LOCK:
        c = _conn()
        try:
            cur = c.execute("""INSERT INTO devices(device_ip, enabled) VALUES(?,?)
                ON CONFLICT(device_ip) DO UPDATE SET enabled=excluded.enabled""",
                (device_ip, 1 if enabled else 0))
            c.commit()
        finally:
            c.close()
    return True, ''


def get_disabled_devices():
    """返回被禁用的设备 IP 集合。"""
    c = _conn()
    rows = c.execute("SELECT device_ip FROM devices WHERE enabled=0").fetchall()
    c.close()
    return {r['device_ip'] for r in rows}


# ---------- 排除 IP 管理 ----------
def get_excluded_ips():
    """返回排除 IP 集合（命中即丢弃，不入库、不调网站名查询）。"""
    c = _conn()
    rows = c.execute("SELECT ip FROM excluded_ips").fetchall()
    c.close()
    return {r['ip'] for r in rows}


def list_excluded_ips():
    """返回排除 IP 列表（含备注、添加时间）。"""
    c = _conn()
    rows = c.execute("SELECT ip, note, created_at FROM excluded_ips ORDER BY created_at DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def add_excluded_ip(ip, note=''):
    """添加排除 IP。返回 (ok, msg)。"""
    ip = str(ip or '').strip()
    if not ip:
        return False, 'IP 不能为空'
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, '无效的 IP 地址'
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("INSERT OR IGNORE INTO excluded_ips (ip, note, created_at) VALUES (?,?,datetime('now','localtime'))",
                      (ip, str(note or '').strip()))
            c.commit()
        finally:
            c.close()
    return True, 'ok'


def remove_excluded_ip(ip):
    """移除排除 IP。"""
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("DELETE FROM excluded_ips WHERE ip=?", (str(ip or '').strip(),))
            c.commit()
        finally:
            c.close()


# ---------- 终端 CSV 导入导出 / 删除 ----------
def export_hosts():
    """导出全部终端（CSV）。"""
    c = _conn()
    rows = c.execute("SELECT mac, ip, hostname, note, first_seen, last_seen FROM hosts ORDER BY last_seen DESC").fetchall()
    c.close()
    return [dict(r) for r in rows]


def normalize_mac(mac):
    """MAC 规范化：统一为分隔符 '-'、去掉两端空白、转大写（支持 ':' 分隔自动转 '-'）。"""
    if not mac:
        return ''
    m = str(mac).strip().replace(':', '-').replace('.', '-').replace(' ', '').upper()
    # 去掉多余分隔符（如 aa-bb-cc-dd-ee-ff 标准 6 组）
    parts = [x for x in m.split('-') if x]
    if len(parts) == 6 and all(len(p) in (1, 2) for p in parts):
        m = '-'.join(p.zfill(2) if len(p) == 1 else p for p in parts)
    return m


def import_host_rows(rows):
    """批量导入终端，以 MAC 为主键自动覆盖。rows: [{mac, ip, hostname, note, first_seen, last_seen}]。
    返回 (ok, imported, skipped, err)。"""
    if not rows:
        return False, 0, 0, '文件为空或没有有效数据'
    with _WRITE_LOCK:
        c = _conn()
        imported = skipped = 0
        try:
            for r in rows:
                mac = normalize_mac(r.get('mac'))
                if not mac:
                    skipped += 1
                    continue
                ip = (r.get('ip') or '').strip() or None
                hostname = (r.get('hostname') or '').strip() or ''
                note = (r.get('note') or '').strip() or ''
                first = (r.get('first_seen') or '').strip() or None
                last = (r.get('last_seen') or '').strip() or None
                c.execute("""INSERT INTO hosts(mac, ip, hostname, first_seen, last_seen, note)
                    VALUES (?,?,?,?,?,?)
                    ON CONFLICT(mac) DO UPDATE SET
                      ip=excluded.ip, hostname=excluded.hostname,
                      first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                      note=excluded.note""",
                    (mac, ip, hostname, first, last, note))
                imported += 1
            c.commit()
            return True, imported, skipped, ''
        except Exception as e:
            c.rollback()
            return False, imported, skipped, '导入失败: ' + str(e)
        finally:
            c.close()


def delete_host(mac):
    """删除终端记录。返回 (ok, err)。删除后若 DHCP 日志再次出现，将自动重新添加。"""
    if not mac:
        return False, '缺少 MAC'
    with _WRITE_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM hosts WHERE mac=?", (mac,))
            c.commit()
            return (cur.rowcount > 0), '' if cur.rowcount else '终端不存在'
        finally:
            c.close()


# ---------- 系统设置 ----------
def get_setting(key, default=None):
    c = _conn()
    row = c.execute("CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)").fetchall()
    r = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
    c.close()
    return r[0] if r else default


def set_setting(key, value):
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                      (key, str(value)))
            c.commit()
        finally:
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


# ---------- 域名/IP ↔ 网站名 数据层（对接 site-name-service） ----------

def cache_lookup(domain):
    """查 24h 缓存表，返回未过期的记录 dict；未命中或已过期返回 None。"""
    c = _conn()
    r = c.execute("SELECT domain,site_name,geo_tag,expire_at FROM domain_cache WHERE domain=?", (domain,)).fetchone()
    c.close()
    if not r:
        return None
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if r['expire_at'] and r['expire_at'] <= now:
        return None
    return dict(r)


def cache_put(domain, site_name, geo_tag, ttl_hours=24):
    """写入缓存表（域名IP 唯一），设置 ttl 小时后过期。"""
    expire = (datetime.now() + timedelta(hours=ttl_hours)).strftime('%Y-%m-%d %H:%M:%S')
    with _WRITE_LOCK:
        c = _conn()
        try:
            c.execute("INSERT INTO domain_cache(domain,site_name,geo_tag,expire_at) VALUES(?,?,?,?) "
                      "ON CONFLICT(domain) DO UPDATE SET site_name=excluded.site_name, "
                      "geo_tag=excluded.geo_tag, expire_at=excluded.expire_at",
                      (domain, site_name or '', geo_tag or '', expire))
            c.commit()
        finally:
            c.close()


def prune_cache():
    """清理过期缓存记录并回写表 A(domain_site)。每小时调用一次。
    回写规则：网站名非空 -> upsert 覆盖(保证最新唯一)；
              网站名为空 -> 表 A 无此域名则作为新记录保存，表 A 已有则直接丢弃(不覆盖旧值)。"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with _WRITE_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT domain,site_name,geo_tag FROM domain_cache WHERE expire_at IS NULL OR expire_at<=?",
                             (now,)).fetchall()
            for r in rows:
                d, sn, gt = r['domain'], r['site_name'] or '', r['geo_tag'] or ''
                if sn:
                    c.execute("INSERT INTO domain_site(domain,site_name,geo_tag,updated_at) VALUES(?,?,?,?) "
                              "ON CONFLICT(domain) DO UPDATE SET site_name=excluded.site_name, "
                              "geo_tag=excluded.geo_tag, updated_at=excluded.updated_at",
                              (d, sn, gt, now))
                else:
                    exist = c.execute("SELECT 1 FROM domain_site WHERE domain=?", (d,)).fetchone()
                    if not exist:
                        c.execute("INSERT INTO domain_site(domain,site_name,geo_tag,updated_at) VALUES(?,?,?,?)",
                                  (d, '', '', now))
            if rows:
                c.execute("DELETE FROM domain_cache WHERE expire_at IS NULL OR expire_at<=?", (now,))
                c.commit()
        finally:
            c.close()
    return len(rows)


def clear_cache():
    """清空域名缓存表(domain_cache)。后台"清空缓存"按钮调用，返回清空条数。"""
    with _WRITE_LOCK:
        c = _conn()
        try:
            n = c.execute("DELETE FROM domain_cache").rowcount
            c.commit()
        finally:
            c.close()
    return n


def cache_count():
    """返回域名缓存表(domain_cache)当前条数，供后台显示。"""
    c = _conn()
    n = c.execute("SELECT COUNT(*) FROM domain_cache").fetchone()[0]
    c.close()
    return n


def site_infos(domains):
    """批量查表 A，返回 {domain: {'site_name':..., 'geo_tag':...}}，仅含表 A 已有的域名。供展示用。"""
    out = {}
    if not domains:
        return out
    keys = [d for d in dict.fromkeys(domains) if d]
    if not keys:
        return out
    c = _conn()
    for i in range(0, len(keys), 200):
        chunk = keys[i:i + 200]
        qmarks = ','.join('?' * len(chunk))
        try:
            rows = c.execute(f"SELECT domain,site_name,geo_tag FROM domain_site WHERE domain IN ({qmarks})", chunk).fetchall()
        except sqlite3.OperationalError:
            rows = []
        for r in rows:
            out[r['domain']] = {'site_name': r['site_name'] or '', 'geo_tag': r['geo_tag'] or ''}
    c.close()
    return out


def get_site_info(domain):
    """单条查表 A，返回 (site_name, geo_tag)。"""
    if not domain:
        return '', ''
    info = site_infos([domain]).get(domain)
    return (info['site_name'], info['geo_tag']) if info else ('', '')

