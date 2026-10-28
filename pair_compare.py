# -*- coding: utf-8 -*-
"""两文件成对对比工具。

用法：python pair_compare.py <上网行为文件> <behavior_ctl文件> [输出目录]
以「日志原始时间戳 + 终端IP」为配对键逐条对比两个文件，
把非成对（仅一边出现 / 两边数量不等）的日志单独输出。
输出：<输出目录>/非成对日志.txt 、<输出目录>/对比摘要.txt
"""
import re
import collections
import os
import sys

RE_TIME = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
RE_IP_WEB = re.compile(r'a:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
RE_IP_CTL = re.compile(r'主机IP[:：]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def parse(path, ip_pat):
    mp = collections.defaultdict(list)
    bad = []
    total = 0
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line.strip():
            continue
        total += 1
        times = RE_TIME.findall(line)
        t = times[1] if len(times) >= 2 else (times[0] if times else '')
        m = ip_pat.search(line)
        ip = m.group(1) if m else ''
        if not t or not ip:
            bad.append(line)
            continue
        mp[(t, ip)].append(line)
    return mp, bad, total


def main():
    if len(sys.argv) < 3:
        print('用法: python pair_compare.py <web_file> <ctl_file> [out_dir]')
        sys.exit(2)
    web_f, ctl_f = sys.argv[1], sys.argv[2]
    out_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.dirname(os.path.abspath(web_f))
    os.makedirs(out_dir, exist_ok=True)
    NONPAIR = os.path.join(out_dir, '非成对日志.txt')
    SUMMARY = os.path.join(out_dir, '对比摘要.txt')

    web, web_bad, web_total = parse(web_f, RE_IP_WEB)
    ctl, ctl_bad, ctl_total = parse(ctl_f, RE_IP_CTL)

    keys = set(web) | set(ctl)
    paired_keys = 0
    mismatch_keys = []
    only_web = []
    only_ctl = []
    nonpair_lines = []

    for k in keys:
        w = len(web.get(k, []))
        c = len(ctl.get(k, []))
        if w and c:
            if w == c:
                paired_keys += 1
            else:
                mismatch_keys.append((k, w, c))
                if w > c:
                    for line in web[k][: w - c]:
                        nonpair_lines.append(('[上网行为]', line))
                else:
                    for line in ctl[k][: c - w]:
                        nonpair_lines.append(('[behavior_ctl]', line))
        elif w and not c:
            only_web.append((k, w))
            for line in web[k]:
                nonpair_lines.append(('[上网行为]', line))
        elif c and not w:
            only_ctl.append((k, c))
            for line in ctl[k]:
                nonpair_lines.append(('[behavior_ctl]', line))

    paired_lines = sum(len(web.get(k, [])) for k in keys
                       if k in web and k in ctl and len(web[k]) == len(ctl[k]))

    with open(NONPAIR, 'w', encoding='utf-8') as f:
        f.write('# 非成对日志（按 日志时间+IP 配对后，仅出现在一边 / 两边数量不等的条目）\n')
        f.write('# 来源标签: [上网行为] / [behavior_ctl]  共 %d 行\n' % len(nonpair_lines))
        if not nonpair_lines:
            f.write('# 无非成对日志\n')
        for src, line in nonpair_lines:
            f.write(src + ' ' + line + '\n')

    s = []
    s.append('WEB_total=%d CTL_total=%d' % (web_total, ctl_total))
    s.append('WEB_parsed=%d CTL_parsed=%d' % (web_total - len(web_bad), ctl_total - len(ctl_bad)))
    s.append('WEB_unparsed=%d CTL_unparsed=%d' % (len(web_bad), len(ctl_bad)))
    s.append('unique_keys=%d' % len(keys))
    s.append('paired_keys=%d paired_lines=%d' % (paired_keys, paired_lines))
    s.append('mismatch_keys=%d mismatch_lines=%d' % (len(mismatch_keys), sum(
        max(len(web.get(k, [])), len(ctl.get(k, []))) - min(len(web.get(k, [])), len(ctl.get(k, [])))
        for k, _, _ in mismatch_keys)))
    s.append('only_web_keys=%d only_web_lines=%d' % (len(only_web), sum(x[1] for x in only_web)))
    s.append('only_ctl_keys=%d only_ctl_lines=%d' % (len(only_ctl), sum(x[1] for x in only_ctl)))
    s.append('nonpair_total_lines=%d' % len(nonpair_lines))
    with open(SUMMARY, 'w', encoding='ascii') as f:
        f.write('\n'.join(s) + '\n')

    print('done: %s / %s' % (NONPAIR, SUMMARY))


if __name__ == '__main__':
    main()
