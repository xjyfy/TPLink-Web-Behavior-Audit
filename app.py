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


# ---------- 页面 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        admin = db.get_admin()
        if admin and u == admin['username'] and db.verify_pw(p, admin['pw_hash']):
            session['user'] = u
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


@app.route('/full/<chart_type>')
@login_required
def full_page(chart_type):
    titles = {
        'domains': '热门网站 - 完整列表',
        'apps': '热门应用 - 完整列表',
        'app_categories': '应用类别 - 完整列表',
        'protocol_top': '网络协议 - 完整列表',
        'hosts': '终端 IP - 完整列表',
    }
    return render_template('full.html', chart_type=chart_type, title=titles.get(chart_type, '完整统计'))


# ---------- 统计 API ----------
@app.route('/api/summary')
@login_required
def api_summary():
    return jsonify(db.summary())


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


def _range():
    return request.args.get('start') or None, request.args.get('end') or None


@app.route('/api/stats/trend')
@login_required
def api_trend():
    return jsonify(db.trend(int(request.args.get('hours', 24))))


@app.route('/api/stats/online_trend')
@login_required
def api_online_trend():
    return jsonify(db.online_trend(int(request.args.get('hours', 24))))


@app.route('/api/stats/hosts')
@login_required
def api_stat_hosts():
    s, e = _range()
    return jsonify(db.top_hosts(int(request.args.get('limit', 10)), s, e))


@app.route('/api/stats/domains')
@login_required
def api_domains():
    s, e = _range()
    return jsonify(db.top_domains(int(request.args.get('limit', 10)), s, e))


@app.route('/api/stats/app_categories')
@login_required
def api_app_cats():
    s, e = _range()
    return jsonify(db.app_categories(s, e))


@app.route('/api/stats/apps')
@login_required
def api_apps():
    s, e = _range()
    return jsonify(db.top_apps(int(request.args.get('limit', 10)), s, e))


@app.route('/api/stats/protocol_top')
@login_required
def api_protocol_top():
    s, e = _range()
    return jsonify(db.protocol_top(s, e))


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
    }
    if chart_type not in handlers:
        return jsonify({'error': 'unknown chart'}), 404
    all_rows = handlers[chart_type]()
    total = len(all_rows)
    paged = all_rows[(page-1)*size:page*size]
    return jsonify({'total': total, 'page': page, 'size': size, 'rows': paged})


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
    return jsonify(db.list_hosts(kw))


@app.route('/api/hosts/note', methods=['POST'])
@login_required
def api_host_note():
    data = request.get_json(force=True)
    mac = data.get('mac'); note = data.get('note', '')
    if not mac:
        return jsonify({'ok': False, 'error': '缺少 mac'}), 400
    db.set_host_note(mac, note)
    return jsonify({'ok': True})


# ---------- 数据来源设备 ----------
@app.route('/api/devices')
@login_required
def api_devices():
    return jsonify(db.list_devices())


@app.route('/api/devices/name', methods=['POST'])
@login_required
def api_device_name():
    data = request.get_json(force=True)
    ip = data.get('device_ip'); name = data.get('custom_name', '')
    if not ip:
        return jsonify({'ok': False, 'error': '缺少 device_ip'}), 400
    db.set_device_name(ip, name)
    return jsonify({'ok': True})


# ---------- 系统设置 ----------
@app.route('/api/settings', methods=['GET'])
@login_required
def api_get_settings():
    days = db.get_setting('keep_days', config.KEEP_DAYS)
    return jsonify({'keep_days': int(days)})


@app.route('/api/settings', methods=['POST'])
@login_required
def api_set_settings():
    data = request.get_json(force=True)
    days = int(data.get('keep_days', 90))
    if days < 1 or days > 3650:
        return jsonify({'ok': False, 'error': '保留天数须在 1-3650 之间'}), 400
    db.set_setting('keep_days', days)
    return jsonify({'ok': True, 'keep_days': days})


@app.route('/api/restart', methods=['POST'])
@login_required
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
def api_clear():
    data = request.get_json(force=True)
    start = data.get('start'); end = data.get('end')
    if not start or not end:
        return jsonify({'ok': False, 'error': '需要 start 和 end'}), 400
    n = db.delete_range(start, end)
    return jsonify({'ok': True, 'deleted': n})


# ---------- 改密 ----------
@app.route('/api/change_password', methods=['POST'])
@login_required
def api_change_pw():
    data = request.get_json(force=True)
    ok = db.change_password(data.get('old_password', ''), data.get('new_password', ''))
    return jsonify({'ok': ok})


# ---------- 导入历史 CSV（TP-Link 导出格式） ----------
@app.route('/api/import_csv', methods=['POST'])
@login_required
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
    syslogd.start_async()
    threading.Thread(target=_prune_loop, daemon=True).start()
    print(f"[web] 后台地址 http://localhost:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False)
