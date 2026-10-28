# -*- coding: utf-8 -*-
"""原始日志分流启动器（控制端）。"""
import os
import sys
import io
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'data')
CTL = os.path.join(DATA, 'capture_ctl.txt')
print('capture.py re-push test')
