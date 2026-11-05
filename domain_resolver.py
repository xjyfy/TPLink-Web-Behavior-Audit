# -*- coding: utf-8 -*-
"""域名/IP → 网站名 解析对接服务（site-name-service 4.0）。

入库时异步解析：先查 24h 缓存表，命中跳过；未命中并发调用接口并写入缓存（含空值/超时）。
- 只用接口1 /api/v1/resolve（已含 geo_tag），只取 status=1 的网站名与 geo_tag，其它状态视为空值。
- 并发默认 20（后台可在 settings 表修改 dns_concurrency）。
- 单次查询 2 秒未返回视为超时；连续超时 >100 条熔断，停止查询半小时后自动恢复。
- Base URL 默认 http://127.0.0.1:888（后台可改 dns_base_url / dns_token）。
"""
import json
import re
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor

import config
import db

DEFAULT_BASE_URL = 'http://127.0.0.1:888'
DEFAULT_TOKEN = 'BnaJmyQmruUw5-nJhP7iYVeFxckeMKjrC7o-svENxU8'
TIMEOUT = 2
BREAKER_THRESHOLD = 100   # 连续超时条数阈值
BREAKER_SECONDS = 1800    # 熔断时长（半小时）

# 禁用系统代理：SYSTEM/watchdog 环境下 urllib 会走系统代理访问 127.0.0.1:888 被拦成 503，
# 必须强制直连（ProxyHandler({})）才能打到本机 site-name-service。
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_running = True
_lock = threading.Lock()
_cache_write_lock = threading.Lock()   # 串行化 cache_put 写库，避免多线程并发写 WAL 触发 database is locked
_pending = set()          # 待解析域名（去重）
_wake = threading.Event()
_conn_errors = 0          # 连续超时/异常计数
_breaker_until = 0.0      # 熔断截止时间戳（0 = 未熔断）


# ---------- 配置读取（来自 settings 表，后台可改） ----------
# 全部配置合并成一次读取 + 5 秒 TTL 缓存：入库路径每条日志会调 submit()，
# 解析线程每个域名还要读 base/token/concurrency，原实现每次都新建一次 SQLite 连接
# （Windows 下打开 4.8G 库连接的开销很明显），高峰时形成连接风暴、单核吃满。
_cfg = {'base': DEFAULT_BASE_URL, 'token': DEFAULT_TOKEN, 'conc': 20, 'enabled': True, 't': 0.0}
_cfg_lock = threading.Lock()


def _refresh_cfg():
    try:
        host = (db.get_setting('dns_host', '127.0.0.1') or '127.0.0.1').strip().rstrip('/')
        port = db.get_setting('dns_port', 888)
        token = db.get_setting('dns_token', DEFAULT_TOKEN) or DEFAULT_TOKEN
        conc = max(1, int(db.get_setting('dns_concurrency', 20)))
        enabled = db.get_setting('dns_enabled', '1') != '0'
    except Exception:
        return
    # 并发上限 32：线程再多只会增加 GIL 争用与上下文切换，对本地 2ms 级接口没有收益
    _cfg.update(base=f"http://{host}:{port}", token=token, conc=min(conc, 32),
                enabled=enabled, t=time.time())


def _cfg_get():
    if time.time() - _cfg['t'] >= 5:
        with _cfg_lock:
            if time.time() - _cfg['t'] >= 5:
                _refresh_cfg()
    return _cfg


def _enabled():
    """网站名称查询开关：settings.dns_enabled，'0'=关闭，其它=开启（默认开启）。"""
    return _cfg_get()['enabled']


def _base():
    """接口服务器地址与端口（settings.dns_host / dns_port），默认 http://127.0.0.1:888。"""
    return _cfg_get()['base']


def _token():
    return _cfg_get()['token']


def _concurrency():
    return _cfg_get()['conc']


# ---------- 域名 / IP 提取 ----------
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', re.IGNORECASE)


def _is_valid_ipv4(s):
    for part in s.split('.'):
        if not 0 <= int(part) <= 255:
            return False
    return True


def extract_domain(s):
    """从 URL / 域名 / IPv4 文本中提取可查询的域名或 IPv4；无法提取返回 None。
    URL 需先剥离协议、端口、路径、查询串，防止接口报错。"""
    if not s:
        return None
    s = s.strip().strip('。，,；;')
    if not s:
        return None
    s2 = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', s)
    host = s2.split('/')[0].split('?')[0].split('#')[0].strip()
    host = re.sub(r':\d+$', '', host).strip()
    if not host:
        return None
    if _IPV4_RE.match(host):
        return host if _is_valid_ipv4(host) else None
    if _DOMAIN_RE.match(host):
        return host.lower()
    return None


# ---------- 单条接口调用 ----------
def _resolve_one(domain):
    """调用接口1解析单个域名/IP，返回 (site_name, geo_tag, ok)。
    ok=True 表示接口正常响应（status=1 有值、status 0/2/-1 为空值，均写缓存）；
    ok=False 表示超时/异常（不写缓存，下次日志命中可重试，避免空值占位 24h 无法更新）。"""
    global _conn_errors, _breaker_until
    url = f"{_base()}/api/v1/resolve?domain={urllib.parse.quote(domain)}"
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {_token()}'})
    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
        with _lock:
            _conn_errors = 0  # 成功：重置连续超时计数
        if data.get('status') == 1:
            return data.get('site_name') or '', data.get('geo_tag') or '', True
        return '', '', True  # status 0/2/-1 正常响应视为空值，仍写缓存
    except Exception:
        with _lock:
            _conn_errors += 1
            if _conn_errors > BREAKER_THRESHOLD:
                _breaker_until = time.time() + BREAKER_SECONDS
                print(f"[resolver] 连续超时超过 {BREAKER_THRESHOLD} 条，熔断停止查询 {BREAKER_SECONDS//60} 分钟")
        return '', '', False  # 超时/异常：不写缓存


# 模块级线程池：原实现每批 _pending 都新建一个 ThreadPoolExecutor，高峰时反复创建/销毁
# 大量线程会显著抬高 CPU 并拖慢入库，故改为复用；并发数变化时按需重建。
_pool = None
_pool_size = 0
_pool_lock = threading.Lock()


def _get_pool():
    global _pool, _pool_size
    n = _concurrency()
    with _pool_lock:
        if _pool is None or n != _pool_size:
            old = _pool
            _pool = ThreadPoolExecutor(max_workers=n)
            _pool_size = n
            if old is not None:
                try:
                    old.shutdown(wait=False)
                except Exception:
                    pass
        return _pool


def _run_batch(todo):
    """并发解析一批未缓存域名并写缓存。复用模块级线程池，避免每批新建线程的开销。"""
    if not todo:
        return
    pool = _get_pool()

    def work(d):
        sn, gt, ok = _resolve_one(d)
        if not ok:
            return  # 超时/异常：不写缓存，避免空值占位 24h 无法更新
        try:
            with _cache_write_lock:
                db.cache_put(d, sn, gt)
        except Exception as e:
            print('[resolver] 写缓存失败:', d, e)
            return
        with _mem_lock:
            _mem[d] = time.time() + _MEM_TTL

    list(pool.map(work, todo))


# 已解析域名的内存命中表：domain -> 过期时间戳。缓存命中时连数据库都不用查，
# 这是解析路径最大的 CPU 来源（原实现每次循环都要对全部待解析域名批量查库）。
_mem = {}
_mem_lock = threading.Lock()
_MEM_TTL = 24 * 3600
# 每轮最多处理的域名数，避免一轮 list/查缓存的 Python 开销随积压量线性膨胀
_MAX_BATCH = 1000


def _worker():
    global _breaker_until, _conn_errors
    while _running:
        with _lock:
            if len(_pending) > _MAX_BATCH:
                items = list(_pending)[:_MAX_BATCH]
                _pending.difference_update(items)
            else:
                items = list(_pending)
                _pending.clear()
        if not items:
            # 必须先 clear 再 wait：Event 处于 set 状态时 wait() 会立即返回，
            # 原实现只 set 不 clear，导致 wait 变成 100% CPU 的空转死循环。
            _wake.clear()
            _wake.wait(timeout=3)
            continue
        if _breaker_until:
            if time.time() < _breaker_until:
                # 熔断中：把本批原样放回待解析集合（不丢弃），并休眠等待，避免忙等空转吃满 CPU
                with _lock:
                    _pending.update(items)
                time.sleep(5)
                continue
            with _lock:
                _breaker_until = 0.0
                _conn_errors = 0  # 熔断恢复：重置计数
        # 先过内存命中表（绝大多数重复域名在这里就结束，不查库）
        now = time.time()
        with _mem_lock:
            items = [d for d in items if _mem.get(d, 0) <= now]
        # 再落到 24h 缓存表（进程重启后内存表为空，靠它兜底）
        try:
            hit_set = db.cache_lookup_many(items)
        except Exception:
            hit_set = set()
        if hit_set:
            with _mem_lock:
                exp = now + _MEM_TTL
                for d in hit_set:
                    _mem[d] = exp
        todo = [d for d in items if d not in hit_set]
        _run_batch(todo)


def _cache_cleaner():
    """每小时清理过期缓存并回写表 A。"""
    while _running:
        try:
            n = db.prune_cache()
            if n:
                print(f"[resolver] 清理过期缓存 {n} 条并回写")
        except Exception as e:
            print('[resolver] 缓存清理失败:', e)
        # 同步清理内存命中表的过期项，防止唯一域名长期累积占内存
        try:
            now = time.time()
            with _mem_lock:
                for d in [d for d, e in _mem.items() if e <= now]:
                    _mem.pop(d, None)
        except Exception:
            pass
        time.sleep(3600)


def submit(domain):
    """把日志中解析出的域名/IP 加入待解析队列（去重、不阻塞）。查询开关关闭时不解析。"""
    if not domain or not _enabled():
        return
    # 内存命中：该域名已完成解析，直接丢弃，避免进入待解析集合反复查库
    if _mem.get(domain, 0) > time.time():
        return
    with _lock:
        _pending.add(domain)
    _wake.set()


def reset():
    """手动重置域名解析熔断状态（供管理界面使用，不重启）。
    清除熔断截止时间、重置连续超时计数，并唤醒 worker 立即检查待解析队列。"""
    global _breaker_until, _conn_errors
    with _lock:
        _breaker_until = 0.0
        _conn_errors = 0
    _wake.set()
    print('[resolver] 熔断状态已手动重置')


def start():
    """启动解析 worker 与缓存清理线程。由 app.py 启动时调用一次。"""
    threading.Thread(target=_worker, daemon=True).start()
    threading.Thread(target=_cache_cleaner, daemon=True).start()
    print(f"[resolver] 域名解析服务已启动，并发={_concurrency()}")
