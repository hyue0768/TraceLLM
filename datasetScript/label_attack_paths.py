#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 2: Label Attack Paths

功能：
- 读取 Script 1 生成的路径级数据集（支持目录或单文件，支持 csv/xlsx/parquet）
- 读取攻击者地址列表（可来自事件 Excel 或独立文件/逗号分隔字符串）
- 读取恶意函数名列表（文件或逗号分隔字符串；支持签名或函数名，大小写不敏感）
- 对每条路径：若包含任一攻击者地址（caller/callee）且包含任一恶意方法，则标记 label=1，否则 label=0
- 将添加 label 列后的数据集输出到指定目录（逐文件输出，且可选合并输出）

用法示例：
  python label_attack_paths.py \
    --input path_datasets \
    --attackers-excel SecurityEvent_dataset_v1.xlsx \
    --malicious-file malicious_methods.txt \
    --output-dir path_datasets_labeled \
    --merge-output
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import List, Set, Tuple, Dict

import pandas as pd


# --------------------------- 日志配置 ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


# --------------------------- 工具函数 ---------------------------
def list_dataset_files(input_path: str) -> List[Path]:
    """列出需要处理的数据文件。
    - 若 input_path 是目录：读取其中匹配 event_*.(csv|xlsx|parquet) 的文件
    - 若 input_path 是文件：直接返回
    """
    p = Path(input_path)
    files: List[Path] = []
    if p.is_dir():
        patterns = [
            'event_*.csv',
            'event_*.xlsx',
            'event_*.parquet',
        ]
        for pat in patterns:
            files.extend(sorted(p.glob(pat)))
    elif p.is_file():
        files = [p]
    else:
        logger.error(f"输入路径不存在: {input_path}")
    return files


def read_dataset(path: Path) -> pd.DataFrame:
    """读取单个数据集文件，返回 DataFrame。"""
    suffix = path.suffix.lower()
    if suffix == '.csv':
        return pd.read_csv(path)
    if suffix in ['.xlsx', '.xls']:
        return pd.read_excel(path)
    if suffix == '.parquet':
        return pd.read_parquet(path)
    raise ValueError(f"不支持的文件格式: {path}")


def write_dataset(df: pd.DataFrame, input_file: Path, output_dir: Path) -> Path:
    """将带有 label 的 DataFrame 写回输出目录，文件名追加 _labeled。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = input_file.stem
    suffix = input_file.suffix.lower()
    labeled_name = f"{stem}_labeled{suffix}"
    out_path = output_dir / labeled_name
    if suffix == '.csv':
        df.to_csv(out_path, index=False, encoding='utf-8')
    elif suffix in ['.xlsx', '.xls']:
        df.to_excel(out_path, index=False, engine='openpyxl')
    elif suffix == '.parquet':
        df.to_parquet(out_path, index=False)
    else:
        raise ValueError(f"不支持的文件格式: {out_path}")
    return out_path


def normalize_address(addr: str) -> str:
    if not isinstance(addr, str):
        return ''
    a = addr.strip().lower()
    return a


def normalize_method_name(method: str) -> Tuple[str, str]:
    """返回 (完整签名小写, 基础函数名小写)。
    - 输入可能形如 "transferFrom(address,address,uint256)" 或 "transferFrom" 或 "0xa9059cbb" 或 其他
    - 若为 hex selector 则原样小写放在完整签名位，基础函数名同完整签名
    """
    if not isinstance(method, str):
        return '', ''
    m = method.strip()
    if not m:
        return '', ''
    m_lower = m.lower()
    if m_lower.startswith('0x') and len(m_lower) in (10, 8, 66):
        # 可能是选择器/哈希，不做进一步解析
        return m_lower, m_lower
    base = m_lower.split('(')[0]
    return m_lower, base


def load_attackers(addresses_excel: str = None, addresses_file: str = None, addresses_list: str = None) -> Set[str]:
    attackers: Set[str] = set()
    # 从 excel 读取（优先），列名尝试 "Address" 或 "address"
    if addresses_excel:
        try:
            df = pd.read_excel(addresses_excel)
            col = 'Address' if 'Address' in df.columns else ('address' if 'address' in df.columns else None)
            if col:
                attackers.update(df[col].dropna().astype(str).map(normalize_address).tolist())
        except Exception as e:
            logger.warning(f"从Excel读取攻击者地址失败: {e}")
    # 从文件读取（txt/csv/json，逐行/逗号分隔/JSON数组）
    if addresses_file and Path(addresses_file).exists():
        try:
            p = Path(addresses_file)
            if p.suffix.lower() == '.json':
                data = json.loads(p.read_text(encoding='utf-8'))
                if isinstance(data, list):
                    attackers.update(normalize_address(x) for x in data)
            else:
                # 文本/CSV：按逗号或换行拆分
                raw = p.read_text(encoding='utf-8')
                parts = [x.strip() for x in raw.replace('\n', ',').split(',') if x.strip()]
                attackers.update(normalize_address(x) for x in parts)
        except Exception as e:
            logger.warning(f"从文件读取攻击者地址失败: {e}")
    # 从命令行逗号分隔读取
    if addresses_list:
        # 兼容：列表或字符串。若为列表，允许空格/逗号混合分隔
        if isinstance(addresses_list, list):
            parts: List[str] = []
            for token in addresses_list:
                if token:
                    parts.extend([x.strip() for x in str(token).replace('\n', ',').split(',') if x.strip()])
        else:
            parts = [x.strip() for x in str(addresses_list).replace('\n', ',').split(',') if x.strip()]
        attackers.update(normalize_address(x) for x in parts)
    return {a for a in attackers if a}


def load_malicious_methods(methods_file: str = None, methods_list: List[str] | str = None) -> Tuple[Set[str], Set[str]]:
    """加载恶意方法名集合，返回 (完整签名集合, 基础名集合)，均为小写。"""
    methods: List[str] = []
    if methods_file and Path(methods_file).exists():
        try:
            p = Path(methods_file)
            if p.suffix.lower() == '.json':
                data = json.loads(p.read_text(encoding='utf-8'))
                if isinstance(data, list):
                    methods.extend([str(x) for x in data])
            else:
                raw = p.read_text(encoding='utf-8')
                methods.extend([x.strip() for x in raw.replace('\n', ',').split(',') if x.strip()])
        except Exception as e:
            logger.warning(f"从文件读取恶意方法失败: {e}")
    if methods_list:
        # 兼容：列表或字符串。若为列表，允许空格/逗号混合分隔
        if isinstance(methods_list, list):
            for token in methods_list:
                if token:
                    methods.extend([x.strip() for x in str(token).replace('\n', ',').split(',') if x.strip()])
        else:
            methods.extend([x.strip() for x in str(methods_list).replace('\n', ',').split(',') if x.strip()])

    full_set: Set[str] = set()
    base_set: Set[str] = set()
    for m in methods:
        full, base = normalize_method_name(m)
        if full:
            full_set.add(full)
        if base:
            base_set.add(base)
    return full_set, base_set


def row_involves_attackers(row: pd.Series, attacker_set: Set[str]) -> bool:
    """判断该路径是否涉及攻击者地址（from/to 均视为涉及）。"""
    # 优先使用 addresses_str 列
    addresses: Set[str] = set()
    if 'addresses_str' in row and isinstance(row['addresses_str'], str) and row['addresses_str']:
        addresses.update(normalize_address(x) for x in row['addresses_str'].split('|') if x)

    # 解析 path_nodes_detail_str 作为补充
    if 'path_nodes_detail_str' in row and isinstance(row['path_nodes_detail_str'], str) and row['path_nodes_detail_str']:
        try:
            nodes = json.loads(row['path_nodes_detail_str'])
            if isinstance(nodes, list):
                for n in nodes:
                    f = normalize_address(n.get('from', '')) if isinstance(n, dict) else ''
                    t = normalize_address(n.get('to', '')) if isinstance(n, dict) else ''
                    if f:
                        addresses.add(f)
                    if t:
                        addresses.add(t)
        except Exception:
            pass

    # 也纳入 attacker_address 列（如果存在）
    if 'attacker_address' in row and isinstance(row['attacker_address'], str):
        aa = normalize_address(row['attacker_address'])
        if aa:
            addresses.add(aa)

    return len(addresses.intersection(attacker_set)) > 0


def row_contains_malicious_methods(row: pd.Series, mal_full: Set[str], mal_base: Set[str]) -> bool:
    """判断该路径是否包含恶意方法。"""
    methods: Set[str] = set()

    # methods_str（优先）
    if 'methods_str' in row and isinstance(row['methods_str'], str) and row['methods_str']:
        for m in row['methods_str'].split('|'):
            full, base = normalize_method_name(m)
            if full:
                methods.add(full)
            if base:
                methods.add(base)

    # path_nodes_detail_str 补充
    if 'path_nodes_detail_str' in row and isinstance(row['path_nodes_detail_str'], str) and row['path_nodes_detail_str']:
        try:
            nodes = json.loads(row['path_nodes_detail_str'])
            if isinstance(nodes, list):
                for n in nodes:
                    if isinstance(n, dict):
                        m = n.get('method', '')
                        full, base = normalize_method_name(m)
                        if full:
                            methods.add(full)
                        if base:
                            methods.add(base)
        except Exception:
            pass

    # 交集判断
    if methods.intersection(mal_full):
        return True
    if methods.intersection(mal_base):
        return True
    return False


def label_dataframe(df: pd.DataFrame, attacker_set: Set[str], mal_full: Set[str], mal_base: Set[str]) -> pd.DataFrame:
    """对 DataFrame 打标签并返回副本。"""
    if df is None or df.empty:
        return df

    def label_row(row: pd.Series) -> int:
        involves = row_involves_attackers(row, attacker_set)
        contains = row_contains_malicious_methods(row, mal_full, mal_base)
        return int(involves and contains)

    df = df.copy()
    df['label'] = df.apply(label_row, axis=1)
    return df


# --------------------------- CLI 主流程 ---------------------------
def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Script 2: Label Attack Paths')
    parser.add_argument('--input', required=True, help='输入路径：目录（包含 event_*.csv/xlsx/parquet）或单文件')
    parser.add_argument('--output-dir', default='path_datasets_labeled', help='输出目录，默认 path_datasets_labeled')

    # 攻击者地址来源（至少提供一种）
    parser.add_argument('--attackers-excel', help='包含 Address 列的 Excel 文件（与 Script 1 相同）')
    parser.add_argument('--attackers-file', help='包含地址的txt/csv/json文件')
    parser.add_argument('--attackers-list', nargs='+', help='空格或逗号分隔的地址列表，例如：--attackers-list 0xabc 0xdef 或 "0xabc,0xdef"')

    # 恶意方法来源（至少提供一种）
    parser.add_argument('--malicious-file', help='包含恶意方法名/签名的txt/csv/json文件')
    parser.add_argument('--malicious-list', nargs='+', help='空格或逗号分隔的恶意方法名/签名/选择器，例如：--malicious-list borrow getUnderlyingPrice 或 "borrow,getUnderlyingPrice"')

    parser.add_argument('--merge-output', action='store_true', help='同时输出合并后的总文件 all_events_labeled.csv')
    return parser.parse_args(argv)


def main(argv: List[str] = None):
    args = parse_args(argv or sys.argv[1:])

    # 准备输入文件
    files = list_dataset_files(args.input)
    if not files:
        logger.error('未找到需要处理的数据文件')
        sys.exit(1)
    logger.info(f"发现 {len(files)} 个待处理文件")

    # 加载攻击者地址
    attacker_set = load_attackers(
        addresses_excel=args.attackers_excel,
        addresses_file=args.attackers_file,
        addresses_list=args.attackers_list,
    )
    if not attacker_set:
        logger.warning('攻击者地址集合为空。若数据集中已包含 attacker_address 列，仍可进行匹配。')
    else:
        logger.info(f"加载攻击者地址 {len(attacker_set)} 个")

    # 加载恶意方法列表
    mal_full, mal_base = load_malicious_methods(
        methods_file=args.malicious_file,
        methods_list=args.malicious_list,
    )
    if not (mal_full or mal_base):
        logger.error('恶意方法列表为空，无法进行标注。')
        sys.exit(1)
    logger.info(f"加载恶意方法：完整/签名 {len(mal_full)} 个，基础名 {len(mal_base)} 个")

    # 逐文件处理
    output_dir = Path(args.output_dir)
    labeled_paths: List[Path] = []
    merged_frames: List[pd.DataFrame] = []

    for idx, f in enumerate(files, 1):
        try:
            logger.info(f"[{idx}/{len(files)}] 处理文件: {f.name}")
            df = read_dataset(f)
            if df is None or df.empty:
                logger.warning(f"文件为空或无法读取: {f}")
                continue

            df_labeled = label_dataframe(df, attacker_set, mal_full, mal_base)
            out_path = write_dataset(df_labeled, f, output_dir)
            labeled_paths.append(out_path)
            merged_frames.append(df_labeled)
            logger.info(f"✅ 写入: {out_path}")
        except Exception as e:
            logger.error(f"处理文件失败 {f}: {e}")

    # 合并输出
    if args.merge_output and merged_frames:
        try:
            merged = pd.concat(merged_frames, ignore_index=True)
            merged_out = output_dir / 'all_events_labeled.csv'
            merged.to_csv(merged_out, index=False, encoding='utf-8')
            logger.info(f"📦 合并输出: {merged_out}")
        except Exception as e:
            logger.error(f"合并输出失败: {e}")

    # 完成
    logger.info("🎉 标注完成！生成文件：")
    for p in labeled_paths:
        logger.info(f"  - {p}")


if __name__ == '__main__':
    main()

