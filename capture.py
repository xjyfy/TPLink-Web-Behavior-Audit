# -*- coding: utf-8 -*-
"""原始日志分流启动器（控制端）。

作用：创建 data/capture_ctl.txt 标记，开启 syslogd 的"原始日志分流"——
把最近收到的 上网行为 / behavior_ctl 两类原始日志，各写到一个文本文件；
N 分钟后自动关闭分流并退出。

用法：python capture.py [分钟数]     # 默认 30 分钟
数据由运行中的主服务（syslogd）写入，本脚本只负责开关标记与显示进度，
不监听端口、不占用 514，也不影响正常入库。
"""
import os
import sys
import io
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'data')
CTL = os.path.join(DATA, 'capture_ctl.txt')
OUT = os.path.join(DATA, 'capture')
F_WEB = os.path.join(OUT, '上网行为.txt')
F_CTL = os.path.join(OUT, 'behavior_ctl.txt')
# 支持命令行参数指定分钟数，默认 30
try:
    _mins = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
except ValueError:
    _mins = 30.0
SECONDS = int(_mins * 60)


def stamp():
    return time.strftime('%H:%M:%S')


def count_lines(p):
    try:
        with open(p, encoding='utf-8') as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def main():
    if os.path.exists(CTL):
        print('已有抓取在运行（capture_ctl.txt 存在）。如需重新开始，请先删除该文件。')
        sys.exit(1)

    end = time.time() + SECONDS
    os.makedirs(OUT, exist_ok=True)
    with open(CTL, 'w', encoding='utf-8') as f:
        f.write(str(end))
    print(f"[{stamp()}] 已开启原始日志分流，{SECONDS//60} 分钟后自动关闭（至 {time.strftime('%H:%M:%S', time.localtime(end))}）")
    print(f"   输出目录: {OUT}")
    print(f"   文件: 上网行为.txt / behavior_ctl.txt")
    try:
        while time.time() < end:
            left = int(end - time.time())
            print(f"[{stamp()}] 剩余 {left:>4}s | 上网行为 {count_lines(F_WEB):>6} 行 | behavior_ctl {count_lines(F_CTL):>6} 行",
                  flush=True)
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n[{stamp()}] 手动中断，关闭分流并退出。")
    finally:
        try:
            os.remove(CTL)
        except FileNotFoundError:
            pass
        print(f"[{stamp()}] 已结束。文件：")
        print(f"    {F_WEB}  ({count_lines(F_WEB)} 行)")
        print(f"    {F_CTL}  ({count_lines(F_CTL)} 行)")


if __name__ == '__main__':
    main()
