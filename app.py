# -*- coding: utf-8 -*-
"""网络日志分析 syslog 采集与分析服务器。"""
import csv
import io
import os
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, session, redirect, url_for, render_template,
                   jsonify, Response, g)

import config
import db

START_TIME = time.time()

# 图标抓取代理（局域网 HTTP 代理，用于访问外网 CDN）
ICON_PROXY = 'http://192.168.31.10:8118'

def _icon_urlopen(url, timeout=5):
    """通过代理或直连打开 URL。"""
    import urllib.request
    proxy_handler = urllib.request.ProxyHandler({'http': ICON_PROXY, 'https': ICON_PROXY})
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    return opener.open(req, timeout=timeout)
import parser
import syslogd

app = Flask(__name__)
app.config['APP_VERSION'] = config.APP_VERSION

# session 密钥
if os.path.exists(config.SECRET_KEY_FILE):
    app.secret_key = open(config.SECRET_KEY_FILE, 'rb').read()
else:
    app.secret_key = os.urandom(32)
    with open(config.SECRET_KEY_FILE, 'wb') as f:
        f.write(app.secret_key)


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get('user'):
            return redirect(url_for('login'))
        return fn(*a, **kw)
    return wrapper


def _current_role():
    return session.get('role') or 'system'


def role_required(*roles):
    """按角色拦截接口。mutate：管理员/系统管理员可写；audit 审计管理员只读。"""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get('user'):
                return jsonify({'ok': False, 'error': '未登录'}), 401
            if _current_role() not in roles:
                return jsonify({'ok': False, 'error': '无权限执行此操作'}), 403
            return fn(*a, **kw)
        return wrapper
    return deco


# 可写操作要求"管理员/系统管理员"；用户管理仅系统管理员
def mutate_required(fn):
    return role_required('system', 'admin')(fn)


def system_required(fn):
    return role_required('system')(fn)


# ---------- 统计结果内存缓存（TTL） ----------
# 总览/报表的统计是对 logs 大表（数百万行）的聚合查询，逐次重查很慢。
# 统计结果本身是"近似实时"即可，用进程内 TTL 缓存（默认 10 秒）避免重复聚合。
_STAT_CACHE = {}
_STAT_CACHE_LOCK = threading.Lock()


def ttl_cache(seconds=10):
    """装饰器：以 函数名 + 请求参数 为 key，缓存视图返回的数据结果 seconds 秒。
    仅用于返回 JSON 数据的统计视图；key 含 request.args，可按时间范围/limit 区分。"""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            key = (fn.__name__, tuple(sorted(request.args.items(multi=True))))
            now = time.time()
            with _STAT_CACHE_LOCK:
                hit = _STAT_CACHE.get(key)
                if hit and now - hit[0] < seconds:
                    return hit[1]
            result = fn(*a, **kw)
            with _STAT_CACHE_LOCK:
                _STAT_CACHE[key] = (now, result)
            return result
        return wrapper
    return deco


# ---------- 页面 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        admin = db.get_admin_by_username(u)
        if admin and db.verify_pw(p, admin['pw_hash']):
            session['user'] = u
            session['role'] = admin['role'] or 'admin'
            return redirect(url_for('dashboard'))
        err = '账号或密码错误'
    return render_template('login.html', err=err)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def root():
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logs')
@login_required
def logs_page():
    return render_template('logs.html')


@app.route('/export')
@login_required
def export_page():
    return render_template('export.html')


@app.route('/hosts')
@login_required
def hosts_page():
    return render_template('hosts.html')


@app.route('/devices')
@login_required
def devices_page():
    return render_template('devices.html')


@app.route('/users')
@login_required
@system_required
def users_page():
    return render_template('users.html')


@app.route('/full/<chart_type>')
@login_required
def full_page(chart_type):
    titles = {
        'domains': '热门网站 - 完整列表',
        'apps': '热门应用 - 完整列表',
        'app_categories': '应用类别 - 完整列表',
        'protocol_top': '网络协议 - 完整列表',
        'hosts': '终端 IP - 完整列表',
        'entertainment_hosts': '娱乐应用 - 终端 IP 完整列表',
    }
    return render_template('full.html', chart_type=chart_type, title=titles.get(chart_type, '完整统计'))


# ---------- 统计 API ----------
@app.route('/api/summary')
@login_required
@ttl_cache(10)
def api_summary():
    return db.summary()


@app.route('/api/host_metrics')
@login_required
def api_host_metrics():
    import metrics
    return jsonify(metrics.host_metrics())


@app.route('/api/uptime')
@login_required
def api_uptime():
    up = int(time.time() - START_TIME)
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return jsonify({'uptime_sec': up, 'days': d, 'hours': h, 'minutes': m, 'seconds': s})


# ---------- 用户管理（仅系统管理员） ----------
@app.route('/api/users', methods=['GET'])
@login_required
@system_required
def api_users_list():
    return jsonify({'rows': db.list_admins(), 'current': session.get('user')})


@app.route('/api/users', methods=['POST'])
@login_required
@system_required
def api_users_add():
    data = request.get_json(force=True)
    ok, err = db.add_admin(data.get('username', ''), data.get('password', ''),
                           data.get('role', 'admin'))
    return jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 400)


@app.route('/api/users/<int:uid>', methods=['PUT'])
@login_required
@system_required
def api_users_update(uid):
    data = request.get_json(force=True)
    ok, err = db.update_admin(uid,
                              data.get('username') if data.get('username') is not None else None,
                              data.get('password') or None,
                              data.get('role') if data.get('role') is not None else None)
    return jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 400)


@app.route('/api/users/<int:uid>', methods=['DELETE'])
@login_required
@system_required
def api_users_delete(uid):
    if uid == session.get('id'):
        pass  # 系统管理员身份由 db 层保护
    ok, err = db.delete_admin(uid)
    return jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 400)


@app.route('/api/categories')
@login_required
@ttl_cache(10)
def api_categories():
    """应用类别统计表全量，供日志查询类别多选下拉（新类别自动出现）。"""
    return jsonify({'rows': db.list_categories()})


# ---------- 应用图标 ----------
# 常见应用名 -> 域名映射（用于抓 favicon）
APP_DOMAIN_MAP = {
    '淘宝': 'taobao.com', '天猫': 'tmall.com', '京东': 'jd.com', '拼多多': 'pinduoduo.com',
    '微信': 'weixin.qq.com', 'QQ': 'im.qq.com', '抖音': 'douyin.com', '快手': 'kuaishou.com',
    '哔哩哔哩': 'bilibili.com', 'B站': 'bilibili.com', '微博': 'weibo.com', '知乎': 'zhihu.com',
    '百度': 'baidu.com', '搜狗': 'sogou.com', '必应': 'bing.com', 'Bing': 'bing.com',
    '支付宝': 'alipay.com', '阿里云': 'aliyun.com', '腾讯云': 'cloud.tencent.com',
    '华为云': 'huaweicloud.com', '网易云音乐': 'music.163.com', 'QQ音乐': 'y.qq.com',
    '爱奇艺': 'iqiyi.com', '腾讯视频': 'v.qq.com', '优酷': 'youku.com', '芒果TV': 'mgtv.com',
    '小红书': 'xiaohongshu.com', '美团': 'meituan.com', '饿了么': 'ele.me', '滴滴': 'didiglobal.com',
    '高德地图': 'amap.com', '百度地图': 'map.baidu.com', '携程': 'ctrip.com', '飞猪': 'fliggy.com',
    'GitHub': 'github.com', 'Google': 'google.com', 'YouTube': 'youtube.com',
    'Zoom': 'zoom.us', '钉钉': 'dingtalk.com', '企业微信': 'work.weixin.qq.com',
    '飞书': 'feishu.cn', 'WPS': 'wps.cn', '迅雷': 'xunlei.com', '百度网盘': 'pan.baidu.com',
    '大众点评': 'dianping.com', '东方财富': 'eastmoney.com', '同花顺': '10jqka.com.cn',
    '招商银行': 'cmbchina.com', '中国银行': 'boc.cn', '建设银行': 'ccb.com',
    '中国农业银行': 'abchina.com', '中国电信': '189.cn', '中国移动': '10086.cn',
    '今日头条': 'toutiao.com', '番茄小说': 'fanqienovel.com', '得物': 'dewu.com',
    '闲鱼': '2.taobao.com', '苏宁易购': 'suning.com', '唯品会': 'vip.com',
    'BOSS直聘': 'zhipin.com', '链家': 'lianjia.com', '向日葵': 'oray.com',
    '夸克': 'quark.cn', 'UC浏览器': 'uc.cn', '小米': 'mi.com', 'OPPO': 'oppo.com',
    'vivo': 'vivo.com', '应用宝': 'appstore.qq.com', '360': '360.cn',
    '喜马拉雅': 'ximalaya.com', '叮咚买菜': 'dingdongmaicai.com',
    'Soul': 'soulapp.cn', 'TapTap': 'taptap.cn', '一点资讯': 'yidianzixun.com',
    '阿里巴巴': 'alibaba.com', 'Outlook': 'outlook.com', 'Apple': 'apple.com',
    'APP_Store': 'apple.com', '微软': 'microsoft.com', 'Microsoft': 'microsoft.com',
    'Office': 'office.com', '华为': 'huawei.com', '腾讯文档': 'docs.qq.com',
    '腾讯地图': 'map.qq.com', '腾讯课堂': 'ke.qq.com', '腾讯新闻': 'news.qq.com',
    '腾讯游戏': 'game.qq.com', 'QQ电脑管家': 'pcmgr.qq.com', 'QQ空间': 'qzone.qq.com',
    'QQ邮箱': 'mail.qq.com', '腾讯bugly': 'bugly.qq.com',
    '幻电科技': 'bilibili.com', 'Tanx': 'tanx.com', 'CNZZ': 'cnzz.com',
    '友盟': 'umeng.com', '极光': 'jpush.cn', '个推': 'getui.com',
    'Wago': 'wago.com', 'Google翻译': 'translate.google.com',
}

# 前缀匹配：应用名以这些开头时，用对应域名（覆盖"腾讯流量""百度公共流量"等变体）
APP_PREFIX_MAP = [
    ('腾讯', 'qq.com'),
    ('百度', 'baidu.com'),
    ('字节跳动', 'bytedance.com'),
    ('抖音', 'douyin.com'),
    ('华为', 'huawei.com'),
    ('小米', 'mi.com'),
    ('OPPO', 'oppo.com'),
    ('vivo', 'vivo.com'),
    ('微信', 'weixin.qq.com'),
    ('QQ', 'qq.com'),
    ('阿里', 'alibaba.com'),
    ('平安', 'pingan.com'),
    ('同花顺', '10jqka.com.cn'),
    ('证券', 'eastmoney.com'),
]


def _resolve_domain(app_name):
    """根据应用名解析对应域名，用于抓 favicon。"""
    if app_name in APP_DOMAIN_MAP:
        return APP_DOMAIN_MAP[app_name]
    for prefix, domain in APP_PREFIX_MAP:
        if app_name.startswith(prefix):
            return domain
    if '.' in app_name:
        return app_name
    return None


# 直接指定图标 URL（用于 favicon 不在根目录的站点）
APP_ICON_URL = {
    '微信': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '企业微信': 'https://res.wx.qq.com/op_res/wxwork_512.png',
    '微信小程序': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信-发送图片': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信-多媒体聊天': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信钱包支付': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信视频号': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信-接收文件': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '微信-接收图片': 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
    '京东': 'https://www.jd.com/favicon.ico',
    '阿里云': 'https://img.alicdn.com/tfs/TB1_ZXuNcfpK1RjSZFOXXa6nFXa-32-32.ico',
}


@app.route('/app_icon/<path:app_name>')
@login_required
def app_icon(app_name):
    import os
    icon_dir = os.path.join(config.BASE_DIR, 'static', 'icons')
    os.makedirs(icon_dir, exist_ok=True)
    # 文件名安全化
    safe = app_name.replace('/', '_').replace('\\', '_').replace(':', '_')
    local = os.path.join(icon_dir, safe + '.png')

    # 透明 1x1 PNG 兜底
    import base64
    transparent = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')

    if os.path.exists(local) and os.path.getsize(local) > 100:
        with open(local, 'rb') as f:
            data = f.read()
        # ICO 文件 magic: 00 00 01 00
        mime = 'image/x-icon' if data[:4] == b'\x00\x00\x01\x00' else 'image/png'
        return Response(data, mimetype=mime)

    # 尝试抓 favicon
    # 1. 先查直接指定的图标 URL
    direct_url = APP_ICON_URL.get(app_name)
    if not direct_url:
        # 前缀匹配
        for prefix, url in APP_ICON_URL.items():
            if app_name.startswith(prefix):
                direct_url = url
                break
    if direct_url:
        try:
            req = urllib.request.Request(direct_url, headers={'User-Agent': 'Mozilla/5.0'})
            with _icon_urlopen(direct_url, timeout=5) as resp:
                data = resp.read()
            if len(data) > 100:
                magic = data[:4]
                if magic in (b'\x00\x00\x01\x00', b'\x89PNG') or data[:2] in (b'\xff\xd8', b'GI'):
                    with open(local, 'wb') as f:
                        f.write(data)
                    mime = 'image/x-icon' if magic == b'\x00\x00\x01\x00' else 'image/png'
                    return Response(data, mimetype=mime)
        except Exception:
            pass

    # 2. 再试标准 /favicon.ico
    domain = _resolve_domain(app_name)
    if domain:
        try:
            for proto in ['https', 'http']:
                try:
                    url = f'{proto}://{domain}/favicon.ico'
                    with _icon_urlopen(url, timeout=5) as resp:
                        data = resp.read()
                    if len(data) > 100:
                        # 校验是图片：ICO(00 00 01 00) 或 PNG(89 50 4E 47) 或 JPEG(FF D8) 或 GIF(47 49)
                        magic = data[:4]
                        if magic in (b'\x00\x00\x01\x00', b'\x89PNG') or data[:2] in (b'\xff\xd8', b'GI'):
                            with open(local, 'wb') as f:
                                f.write(data)
                            mime = 'image/x-icon' if magic == b'\x00\x00\x01\x00' else 'image/png'
                            return Response(data, mimetype=mime)
                except Exception:
                    continue
        except Exception:
            pass

    return Response(transparent, mimetype='image/png')


@app.route('/api/app_icon/<path:app_name>', methods=['POST'])
@login_required
def api_app_icon_upload(app_name):
    """上传/更换某应用的自定义图标。文件保存到 static/icons/<safe>.png，
    即 /app_icon/ 使用的同一缓存目录；保存后自动缓存，后续展示自动使用。"""
    import os
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': '未收到文件'}), 400
    data = f.read()
    if not data:
        return jsonify({'ok': False, 'error': '文件为空'}), 400
    if len(data) > 2 * 1024 * 1024:
        return jsonify({'ok': False, 'error': '图片过大（限 2MB）'}), 400
    # 按文件头校验图片类型：PNG/JPG/GIF/ICO/WEBP
    sig = data[:8]
    valid = (sig.startswith(b'\x89PNG\r\n\x1a\n') or
             sig.startswith(b'\xff\xd8') or
             sig.startswith(b'GIF8') or
             sig.startswith(b'\x00\x00\x01\x00') or
             (sig[:4] == b'RIFF' and data[8:12] == b'WEBP'))
    if not valid:
        return jsonify({'ok': False,
                        'error': '不是有效的图片文件（支持 PNG/JPG/GIF/ICO/WEBP）'}), 400
    icon_dir = os.path.join(config.BASE_DIR, 'static', 'icons')
    os.makedirs(icon_dir, exist_ok=True)
    safe = app_name.replace('/', '_').replace('\\', '_').replace(':', '_')
    local = os.path.join(icon_dir, safe + '.png')
    with open(local, 'wb') as fh:
        fh.write(data)
    # 记录缓存（供后续展示与匹配使用；失败不影响上传）
    try:
        db.init_icons()
        db.set_icon_path(app_name, safe + '.png')
    except Exception:
        pass
    return jsonify({'ok': True, 'name': app_name})


def _range():
    return request.args.get('start') or None, request.args.get('end') or None


@app.route('/api/stats/trend')
@login_required
@ttl_cache(10)
def api_trend():
    return db.trend(int(request.args.get('hours', 24)))


@app.route('/api/stats/online_trend')
@login_required
@ttl_cache(10)
def api_online_trend():
    return db.online_trend(int(request.args.get('hours', 24)))


def _attach_host_notes(rows):
    """为终端 IP 排行行附加备注名（hosts 表按 IP 反查）与在线标记，供总览图表展示。"""
    if not rows:
        return rows
    nm = db.host_note_map_by_ip()
    online = db.online_host_ips(hours=1)
    for r in rows:
        r['note'] = nm.get(r.get('k'), '')
        r['online'] = 1 if r.get('k') in online else 0
    return rows


@app.route('/api/stats/hosts')
@login_required
@ttl_cache(10)
def api_stat_hosts():
    s, e = _range()
    return _attach_host_notes(db.top_hosts(int(request.args.get('limit', 10)), s, e))


@app.route('/api/stats/entertainment_hosts')
@login_required
@ttl_cache(10)
def api_entertainment_hosts():
    s, e = _range()
    return _attach_host_notes(db.entertainment_hosts(int(request.args.get('limit', 10)), s, e))


@app.route('/api/stats/entertainment_host_apps')
@login_required
@ttl_cache(10)
def api_entertainment_host_apps():
    """指定终端在娱乐应用类别下的具体应用及次数（供完整列表页点击 IP 展开明细）。"""
    s, e = _range()
    host = request.args.get('host_ip', '')
    return jsonify({'rows': db.host_entertainment_apps(host, s, e)})


@app.route('/api/stats/host_top')
@login_required
def api_host_top():
    """指定终端使用最多的 10 个应用 + 10 个网站（供终端 IP 完整列表页点击 IP 展开）。"""
    s, e = _range()
    host = request.args.get('host_ip', '')
    if not host:
        return jsonify({'apps': [], 'domains': []})
    return jsonify(db.host_top_apps_domains(host, s, e))


@app.route('/api/stats/domains')
@login_required
@ttl_cache(10)
def api_domains():
    s, e = _range()
    return db.top_domains(int(request.args.get('limit', 10)), s, e)


@app.route('/api/stats/app_categories')
@login_required
@ttl_cache(10)
def api_app_cats():
    s, e = _range()
    return db.app_categories(s, e)


@app.route('/api/stats/apps')
@login_required
@ttl_cache(10)
def api_apps():
    s, e = _range()
    return db.top_apps(int(request.args.get('limit', 10)), s, e)


@app.route('/api/stats/protocol_top')
@login_required
@ttl_cache(10)
def api_protocol_top():
    s, e = _range()
    return db.protocol_top(s, e)


@app.route('/api/stats/all/<chart_type>')
@login_required
def api_stats_all(chart_type):
    s, e = _range()
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 20))
    handlers = {
        'domains': lambda: db.top_domains(10000, s, e),
        'apps': lambda: db.top_apps(10000, s, e),
        'app_categories': lambda: db.app_categories_all(s, e),
        'protocol_top': lambda: db.protocol_top_all(s, e),
        'hosts': lambda: db.top_hosts(10000, s, e),
        'entertainment_hosts': lambda: db.entertainment_hosts_all(s, e),
    }
    if chart_type not in handlers:
        return jsonify({'error': 'unknown chart'}), 404
    all_rows = handlers[chart_type]()
    if chart_type in ('hosts', 'entertainment_hosts'):
        all_rows = _attach_host_notes(all_rows)
    total = len(all_rows)
    paged = all_rows[(page-1)*size:page*size]
    return jsonify({'total': total, 'page': page, 'size': size, 'rows': paged})


@app.route('/api/stats/apps_in_category')
@login_required
def api_apps_in_category():
    """返回指定应用类别下的具体应用明细（供类别完整列表页点击展开）。
    每个应用附带该时间段内使用的终端设备数（devices）。"""
    s, e = _range()
    cat = request.args.get('category', '')
    if not cat:
        return jsonify({'rows': []})
    rows = db.apps_by_category(cat, s, e)
    dev = db.apps_by_category_devices(cat, s, e)
    for r in rows:
        r['devices'] = dev.get(r['k'], 0)
    return jsonify({'rows': rows})


@app.route('/api/stats/app_devices')
@login_required
def api_app_devices():
    """返回指定应用在时间段内使用的终端设备分页列表（供悬浮弹框展示）。"""
    s, e = _range()
    app = request.args.get('app', '')
    if not app:
        return jsonify({'total': 0, 'page': 1, 'size': 20, 'rows': []})
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 20))
    return jsonify(db.app_devices(app, s, e, page, size))


# ---------- 日志查询 API ----------
@app.route('/api/logs')
@login_required
def api_logs():
    start = request.args.get('start') or None
    end = request.args.get('end') or None
    host_ip = request.args.get('host_ip') or None
    event_type = request.args.get('event_type') or None
    app_category = request.args.get('app_category') or None
    app_name = request.args.get('app_name') or None
    keyword = request.args.get('keyword') or None
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 50))
    total, rows = db.query_logs(start, end, host_ip, event_type,
                               app_category, app_name, keyword, page, size)
    note_map = db.host_note_map_by_ip()
    for r in rows:
        r['host_note'] = note_map.get(r.get('host_ip'), '')
    return jsonify({'total': total, 'page': page, 'size': size, 'rows': rows})


# ---------- 终端管理 API ----------
@app.route('/api/hosts')
@login_required
def api_hosts():
    kw = request.args.get('keyword') or None
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 20))
    return jsonify(db.list_hosts_page(kw, page, size))


@app.route('/api/hosts/note', methods=['POST'])
@login_required
@mutate_required
def api_host_note():
    data = request.get_json(force=True)
    mac = data.get('mac'); note = data.get('note', '')
    if not mac:
        return jsonify({'ok': False, 'error': '缺少 mac'}), 400
    db.set_host_note(mac, note)
    return jsonify({'ok': True})


@app.route('/api/hosts/delete', methods=['POST'])
@login_required
@mutate_required
def api_host_delete():
    data = request.get_json(force=True)
    mac = data.get('mac', '')
    ok, err = db.delete_host(mac)
    return jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 400)


@app.route('/api/hosts.csv')
@login_required
def api_hosts_export():
    """导出终端列表为 CSV（mac 主键）。"""
    rows = db.export_hosts()
    buf = io.StringIO()
    buf.write('\ufeff')
    w = csv.writer(buf)
    w.writerow(['mac', 'ip', 'hostname', 'note', 'first_seen', 'last_seen'])
    for r in rows:
        w.writerow([r['mac'], r['ip'], r['hostname'], r['note'],
                    r['first_seen'], r['last_seen']])
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':
                             'attachment; filename=hosts_%s.csv' %
                             datetime.now().strftime('%Y%m%d_%H%M%S')})


@app.route('/api/hosts/import', methods=['POST'])
@login_required
@mutate_required
def api_hosts_import():
    """导入终端 CSV，以 mac 为主键自动覆盖（支持 ':' 分隔自动转 '-'）。"""
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': '未上传文件'}), 400
    rows = []
    reader = csv.DictReader(io.TextIOWrapper(f.stream, encoding='utf-8-sig'))
    for r in reader:
        rows.append({'mac': r.get('mac'), 'ip': r.get('ip'), 'hostname': r.get('hostname'),
                     'note': r.get('note'), 'first_seen': r.get('first_seen'),
                     'last_seen': r.get('last_seen')})
    ok, imported, skipped, err = db.import_host_rows(rows)
    if ok:
        return jsonify({'ok': True, 'imported': imported, 'skipped': skipped})
    return jsonify({'ok': False, 'error': err}), 400


# ---------- 数据来源设备 ----------
@app.route('/api/devices')
@login_required
def api_devices():
    return jsonify(db.list_devices())


@app.route('/api/devices/name', methods=['POST'])
@login_required
@mutate_required
def api_device_name():
    data = request.get_json(force=True)
    ip = data.get('device_ip'); name = data.get('custom_name', '')
    if not ip:
        return jsonify({'ok': False, 'error': '缺少 device_ip'}), 400
    db.set_device_name(ip, name)
    return jsonify({'ok': True})


@app.route('/api/devices/toggle', methods=['POST'])
@login_required
@mutate_required
def api_device_toggle():
    """禁用/启用数据来源设备。被禁用设备的 syslog 将被丢弃。"""
    data = request.get_json(force=True)
    ip = data.get('device_ip')
    enabled = bool(data.get('enabled'))
    if not ip:
        return jsonify({'ok': False, 'error': '缺少 device_ip'}), 400
    ok, err = db.set_device_enabled(ip, enabled)
    if ok:
        syslogd.refresh_disabled_devices()
    return jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 400)


# ---------- 系统设置 ----------
@app.route('/api/settings', methods=['GET'])
@login_required
def api_get_settings():
    days = db.get_setting('keep_days', config.KEEP_DAYS)
    drop = db.get_setting('drop_web_usage', '0')
    return jsonify({'keep_days': int(days), 'drop_web_usage': str(drop) == '1'})


@app.route('/api/settings', methods=['POST'])
@login_required
@mutate_required
def api_set_settings():
    data = request.get_json(force=True)
    if 'keep_days' in data:
        days = int(data.get('keep_days', 90))
        if days < 1 or days > 3650:
            return jsonify({'ok': False, 'error': '保留天数须在 1-3650 之间'}), 400
        db.set_setting('keep_days', days)
    if 'drop_web_usage' in data:
        db.set_setting('drop_web_usage', '1' if data.get('drop_web_usage') else '0')
    return jsonify({'ok': True})


@app.route('/api/restart', methods=['POST'])
@login_required
@mutate_required
def api_restart():
    """重启服务：先返回响应，再由独立脚本杀掉当前进程并重启。"""
    import subprocess, sys, os
    bat = os.path.join(config.BASE_DIR, 'restart.bat')
    # 用 cmd /c start 脱离当前进程
    subprocess.Popen(['cmd', '/c', 'start', '', '/min', bat],
                     cwd=config.BASE_DIR, shell=True)
    return jsonify({'ok': True, 'msg': '服务将在 2 秒后重启...'})


# ---------- 导出 / 清空 ----------
@app.route('/api/export.csv')
@login_required
def api_export():
    start = request.args.get('start') or None
    end = request.args.get('end') or None
    rows = db.export_rows(start, end)
    buf = io.StringIO()
    buf.write('\ufeff')  # BOM for Excel
    w = csv.writer(buf)
    w.writerow(['时间', '设备', '模块', '等级', '终端IP', '事件类型',
                '网站分组', '域名', '网址', '应用类别', '应用名', '原始日志'])
    for r in rows:
        w.writerow([r['ts'], r['device_name'], r['module'], r['level'],
                    r['host_ip'], r['event_type'], r['web_group'], r['domain'],
                    r['url'], r['app_category'], r['app_name'], r['raw']])
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':
                             'attachment; filename=audit_%s.csv' %
                             datetime.now().strftime('%Y%m%d_%H%M%S')})


@app.route('/api/clear', methods=['POST'])
@login_required
@mutate_required
def api_clear():
    data = request.get_json(force=True)
    start = data.get('start'); end = data.get('end')
    if not start or not end:
        return jsonify({'ok': False, 'error': '需要 start 和 end'}), 400
    n = db.delete_range(start, end)
    return jsonify({'ok': True, 'deleted': n})


@app.route('/api/logs/export.csv')
@login_required
def api_logs_export():
    """将当前日志查询结果导出为 CSV。"""
    start = request.args.get('start') or None
    end = request.args.get('end') or None
    host_ip = request.args.get('host_ip') or None
    event_type = request.args.get('event_type') or None
    app_category = request.args.get('app_category') or None
    app_name = request.args.get('app_name') or None
    keyword = request.args.get('keyword') or None
    rows = db.query_logs_all(start, end, host_ip, event_type,
                             app_category, app_name, keyword)
    buf = io.StringIO()
    buf.write('\ufeff')
    w = csv.writer(buf)
    w.writerow(['时间', '设备', '模块', '等级', '终端IP', '事件类型',
                '网站分组', '域名', '网址', '应用类别', '应用名', '原始日志'])
    for r in rows:
        w.writerow([r['ts'], r['device_name'], r['module'], r['level'],
                    r['host_ip'], r['event_type'], r['web_group'], r['domain'],
                    r['url'], r['app_category'], r['app_name'], r['raw']])
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':
                             'attachment; filename=logs_%s.csv' %
                             datetime.now().strftime('%Y%m%d_%H%M%S')})


# ---------- 改密 ----------
@app.route('/api/change_password', methods=['POST'])
@login_required
def api_change_pw():
    data = request.get_json(force=True)
    ok = db.change_password(session.get('user', ''),
                            data.get('old_password', ''), data.get('new_password', ''))
    return jsonify({'ok': ok})


# ---------- 导入历史 CSV（TP-Link 导出格式） ----------
@app.route('/api/import_csv', methods=['POST'])
@login_required
@mutate_required
def api_import_csv():
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': '未上传文件'}), 400
    rows = []
    host_updates = []
    reader = csv.DictReader(io.TextIOWrapper(f.stream, encoding='utf-8-sig'))
    for r in reader:
        module = r.get('功能模块') or parser.detect_module(r.get('日志内容', ''))
        content = r.get('日志内容', '')
        fields = parser.normalize_message(module, content)
        ts = r.get('时间') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # DHCP 只更新终端映射，不进日志
        if fields.get('event_type') == 'dhcp':
            host_updates.append((fields.get('mac'), fields.get('assigned_ip'), ts))
            continue
        rows.append({
            'ts': ts,
            'device_name': r.get('设备名称') or 'TL-ER3228ET',
            'device_ip': r.get('设备IP') or '',
            'module': module,
            'level': r.get('日志等级') or '通知',
            'raw': content,
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
        })
    db.insert_many(rows)
    for mac, ip, ts in host_updates:
        db.upsert_host(mac, ip, ts)
    return jsonify({'ok': True, 'imported': len(rows), 'hosts': len(host_updates)})


# ---------- 启动 ----------
def _prune_loop():
    while True:
        try:
            days = int(db.get_setting('keep_days', config.KEEP_DAYS))
            db.prune(days)
        except Exception as e:
            print('[prune]', e)
        time.sleep(3600)  # 每小时清理一次


if __name__ == '__main__':
    db.init_db()
    threading.Thread(target=db.backfill_hourly, daemon=True).start()  # 后台回填 hourly 汇总表
    syslogd.start_async()
    threading.Thread(target=_prune_loop, daemon=True).start()
    print(f"[web] 后台地址 http://localhost:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False)
