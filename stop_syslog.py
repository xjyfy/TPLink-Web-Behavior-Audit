# -*- coding: utf-8 -*-
"""仅停止 syslog 服务的 python 进程（watchdog.py / app.py 且路径在 syslog 目录）。
供 restart.bat 调用，避免误杀同机运行的 site-name-service 等其他 python 进程。"""
import psutil

killed = []
for p in psutil.process_iter(['name', 'cmdline']):
    try:
        name = p.info['name']
        cmd = ' '.join(p.info['cmdline'] or [])
    except Exception:
        continue
    if name in ('python.exe', 'pythonw.exe') \
            and ('watchdog.py' in cmd or 'app.py' in cmd) \
            and 'syslog' in cmd.lower():
        try:
            p.kill()
            killed.append(p.pid)
        except Exception:
            pass
