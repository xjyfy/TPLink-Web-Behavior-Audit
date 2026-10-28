# -*- coding: utf-8 -*-
"""全局配置：端口、账号、保留策略。首次启动后可按需修改本文件并重启。"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "syslog.db")

# syslog UDP 监听端口（标准 514；Windows 无需管理员即可绑定，但需放行防火墙）
SYSLOG_UDP_HOST = "0.0.0.0"
SYSLOG_UDP_PORT = 514

# Web 后台监听
WEB_HOST = "0.0.0.0"
WEB_PORT = 8080

# 默认管理员（首次初始化写入数据库；登录后可在页面修改密码）
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin123"

# 日志自动清理天数（SQLite 单表建议不超过 30 天；管理员可在网页"导出与清理"页修改）
KEEP_DAYS = 30

# 版本号（展示于后台左上角）
APP_VERSION = "v3.0"

# Flask session 密钥（首次启动随机生成并持久化到 data/.secret_key）
SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret_key")

os.makedirs(DATA_DIR, exist_ok=True)
