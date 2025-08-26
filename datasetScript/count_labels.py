#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统计指定目录下所有 CSV 文件的行数与 label=1 的行数。

默认目录：/home/os/shuzheng/whole_pipeline/path_datasets_labeled

用法：
  python count_labels.py
  python count_labels.py --dir /path/to/dir
"""

import os
import sys
import csv
import argparse
from pathlib import Path


def count_labels_in_csv(csv_path: Path) -> tuple[int, int]:
    """返回 (总行数, label为1的行数)。包含表头的第一行不计入总行数。"""
    total_rows = 0
    label_ones = 0
    try:
        with csv_path.open('r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_rows += 1
                label_val = row.get('label')
                if label_val is None:
                    continue
                # 兼容字符串/数字
                if str(label_val).strip() == '1':
                    label_ones += 1
    except UnicodeDecodeError:
        # 兼容可能的编码
        with csv_path.open('r', encoding='utf-8-sig', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_rows += 1
                label_val = row.get('label')
                if label_val is None:
                    continue
                if str(label_val).strip() == '1':
                    label_ones += 1
    return total_rows, label_ones


def main(argv=None):
    parser = argparse.ArgumentParser(description='统计目录下CSV的总行数与label=1的行数')
    parser.add_argument(
        '--dir',
        default='/home/os/shuzheng/whole_pipeline/path_datasets_labeled',
        help='要统计的目录（默认：/home/os/shuzheng/whole_pipeline/path_datasets_labeled）'
    )
    args = parser.parse_args(argv)

    target_dir = Path(args.dir)
    if not target_dir.exists() or not target_dir.is_dir():
        print(f'目录不存在或不是目录: {target_dir}')
        sys.exit(1)

    csv_files = sorted(target_dir.glob('*.csv'))
    if not csv_files:
        print(f'目录下未找到CSV文件: {target_dir}')
        sys.exit(0)

    grand_total = 0
    grand_label_ones = 0

    for csv_file in csv_files:
        total, ones = count_labels_in_csv(csv_file)
        grand_total += total
        grand_label_ones += ones

    print('统计结果:')
    print(f'- 目录: {target_dir}')
    print(f'- CSV 文件数: {len(csv_files)}')
    print(f'- 总行数: {grand_total}')
    print(f'- label=1 的行数: {grand_label_ones}')
    if grand_total > 0:
        ratio = grand_label_ones / grand_total * 100.0
        print(f'- 占比: {ratio:.2f}%')


if __name__ == '__main__':
    main()

