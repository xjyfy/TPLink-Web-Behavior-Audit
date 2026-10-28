# -*- coding: utf-8 -*-
"""看门狗：启动 app.py，若进程退出则 5 秒后自动重启，并把输出记录到 data/service.log。
配合 SYSTEM 开机自启使用，解决"服务中途退出后无人拉起"的问题。
"""
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(BASE_DIR, "app.py")
LOG_DIR = os.path.join(BASE_DIR, "data")
LOG = os.path.join(LOG_DIR, "service.log")
EXE = sys.executable  # 用运行看门狗的同款 Python 启动 app.py

os.makedirs(LOG_DIR, exist_ok=True)


def stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def start_app():
    log = open(LOG, "a", encoding="utf-8")
    log.write(f"\n===== [{stamp()}] 启动 app.py (pid 待定) =====\n")
    log.flush()
    p = subprocess.Popen(
        [EXE, APP],
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd=BASE_DIR,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return p, log


def main():
    with open(LOG, "a", encoding="utf-8") as bootlog:
        bootlog.write(f"[{stamp()}] watchdog 启动, python={EXE}\n")
    while True:
        try:
            p, log = start_app()
        except Exception as e:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(f"[{stamp()}] 启动 app 失败: {e}\n")
            time.sleep(10)
            continue
        try:
            code = p.wait()
        finally:
            try:
                log.close()
            except Exception:
                pass
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"[{stamp()}] app.py 已退出 (code={code})，5 秒后自动重启\n")
        time.sleep(5)


if __name__ == "__main__":
    main()
