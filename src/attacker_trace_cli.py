import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from web3 import Web3
from hexbytes import HexBytes


def to_checksum(address: str) -> str:
    if not address:
        return address
    try:
        return Web3.to_checksum_address(address)
    except Exception:
        return address


def is_same_address(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    try:
        return Web3.to_checksum_address(a) == Web3.to_checksum_address(b)
    except Exception:
        return a.lower() == b.lower()


def json_default(o: Any) -> str:
    """JSON 序列化回调：将 bytes/HexBytes 转为 0x 开头的十六进制字符串。其他未知类型转为 str。"""
    if isinstance(o, (bytes, bytearray, HexBytes)):
        return "0x" + o.hex()
    return str(o)


_SELECTOR_CACHE: Dict[str, str] = {}


def normalize_hex_str(value: str) -> str:
    """将任意形态的十六进制字符串标准化为单一前缀 0x 开头的小写形式。"""
    if not isinstance(value, str):
        return "0x"
    s = value.lower().strip()
    # 去掉所有前导 0x
    while s.startswith("0x"):
        s = s[2:]
    # 保留仅一个 0x 前缀
    return "0x" + s


def extract_selector(input_data: Union[str, bytes, bytearray, HexBytes, None]) -> str:
    """从交易 input 提取 4-byte 选择器（0x + 8 个十六进制字符，共 10 字符）。若不足返回 "0x"。"""
    if input_data is None:
        return "0x"
    if isinstance(input_data, (bytes, bytearray, HexBytes)):
        hex_str = "0x" + bytes(input_data).hex()
    elif isinstance(input_data, str):
        hex_str = normalize_hex_str(input_data)
    else:
        try:
            hex_str = normalize_hex_str(str(input_data))
        except Exception:
            return "0x"

    # 去掉 0x，仅取前 8 位（4-byte）
    payload = hex_str[2:]
    if len(payload) < 8:
        return "0x"
    return "0x" + payload[:8]


def resolve_function_name(selector: str, timeout_sec: float = 5.0) -> Optional[str]:
    """使用 4byte.directory 解析函数选择器为函数签名。带本地缓存。"""
    if not selector or selector == "0x":
        return None
    if selector in _SELECTOR_CACHE:
        return _SELECTOR_CACHE[selector]

    url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}"
    try:
        resp = requests.get(url, timeout=timeout_sec)
        if resp.status_code != 200:
            return None
        data = resp.json()
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, list) and results:
            # 取第一条（4byte 返回按新增时间倒序；此处简单取首条）
            text_sig = results[0].get("text_signature")
            if isinstance(text_sig, str):
                _SELECTOR_CACHE[selector] = text_sig
                return text_sig
        return None
    except Exception:
        return None


def shrink_trace_inputs(obj: Union[Dict[str, Any], List[Any]]) -> None:
    """递归处理 trace 结构，将 action.input 或 action.data 压缩为 4-byte，并增加 action.function。原地修改。"""
    if isinstance(obj, dict):
        action = obj.get("action")
        if isinstance(action, dict):
            raw = None
            if "input" in action:
                raw = action.get("input")
            elif "data" in action:
                raw = action.get("data")
            if raw is not None:
                selector = extract_selector(raw)
                action["input"] = selector
                # 不覆盖 data，保持仅 input 为规范的 4-byte；其他字段不变
                func = resolve_function_name(selector) or ""
                action["function"] = func
        # 递归处理可能存在的子结构
        for k, v in list(obj.items()):
            if isinstance(v, (dict, list)):
                shrink_trace_inputs(v)
    elif isinstance(obj, list):
        for item in obj:
            shrink_trace_inputs(item)


def scan_relevant_transactions(
    w3: Web3,
    attacker_address: str,
    start_block: int,
    end_block: int,
    progress_interval: int = 0,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scan blocks and collect transactions related to the attacker.

    Returns a tuple of:
      - transactions: list of transaction summaries
      - tx_hashes: list of transaction hashes (hex string)
    """
    transactions: List[Dict[str, Any]] = []
    tx_hashes: List[str] = []

    attacker_checksum = to_checksum(attacker_address)

    latest = w3.eth.block_number
    start_block = max(0, int(start_block))
    end_block = min(int(end_block), int(latest))
    if start_block > end_block:
        start_block, end_block = end_block, start_block

    total_blocks = (end_block - start_block + 1)
    if progress_interval and progress_interval > 0:
        try:
            print(f"Scanning blocks {start_block}-{end_block} (total {total_blocks})...")
        except Exception:
            pass

    for block_num in range(start_block, end_block + 1):
        try:
            block = w3.eth.get_block(block_num, full_transactions=True)
        except Exception as exc:
            print(f"Failed to fetch block {block_num}: {exc}", file=sys.stderr)
            continue

        block_timestamp = int(block.timestamp) if hasattr(block, "timestamp") else None

        for tx in block.transactions:
            try:
                tx_from = tx.get("from") if isinstance(tx, dict) else tx["from"]
                tx_to = tx.get("to") if isinstance(tx, dict) else tx["to"]
                tx_hash = tx.get("hash") if isinstance(tx, dict) else tx.hash
                tx_input = tx.get("input") if isinstance(tx, dict) else tx.input
                tx_value = tx.get("value") if isinstance(tx, dict) else tx.value

                # Normalize hash
                if isinstance(tx_hash, bytes):
                    tx_hash = tx_hash.hex()
                if isinstance(tx_hash, str) and not tx_hash.startswith("0x"):
                    tx_hash = "0x" + tx_hash

                is_contract_creation = tx_to is None and is_same_address(tx_from, attacker_checksum)
                is_from_attacker = is_same_address(tx_from, attacker_checksum)
                is_to_attacker = tx_to is not None and is_same_address(tx_to, attacker_checksum)

                if not (is_from_attacker or is_to_attacker or is_contract_creation):
                    continue

                selector = extract_selector(tx_input)
                func_name = resolve_function_name(selector) or ""

                tx_summary = {
                    "hash": tx_hash,
                    "blockNumber": block_num,
                    "timestamp": block_timestamp,
                    "from": tx_from,
                    "to": tx_to,
                    "value": str(tx_value) if tx_value is not None else "0",
                    # 仅保留 4-byte 选择器（10 字符），其他 input 数据丢弃
                    "input": selector,
                    # 新增解析出的函数名
                    "function": func_name,
                    "isContractCreation": bool(is_contract_creation),
                }
                transactions.append(tx_summary)
                tx_hashes.append(tx_hash)
            except Exception as exc:
                print(f"Failed to process tx in block {block_num}: {exc}", file=sys.stderr)
                continue

        if progress_interval and progress_interval > 0:
            try:
                progressed = (block_num - start_block + 1)
                if progressed % progress_interval == 0 or block_num == end_block:
                    print(f"Progress: {progressed}/{total_blocks} blocks ({block_num} reached)")
            except Exception:
                pass

    return transactions, tx_hashes


def fetch_trace_via_external_service(
    tx_hash: str,
    trace_url: Optional[str],
    trace_api_key: Optional[str],
    timeout_sec: float = 10.0,
) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """Try to fetch trace via a JSON-RPC external service that supports trace_transaction."""
    if not trace_url:
        return None

    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    payload = {
        "jsonrpc": "2.0",
        "method": "trace_transaction",
        "params": [tx_hash],
        "id": 1,
    }
    headers = {"Content-Type": "application/json"}
    if trace_api_key:
        headers["Authorization"] = f"Bearer {trace_api_key}"

    try:
        resp = requests.post(trace_url, headers=headers, json=payload, timeout=timeout_sec)
        if resp.status_code != 200:
            print(f"External trace service HTTP {resp.status_code}", file=sys.stderr)
            return None
        result = resp.json()
        if isinstance(result, dict) and result.get("result") is not None:
            return result["result"]
        if isinstance(result, dict) and result.get("error"):
            print(f"External trace error: {result['error']}", file=sys.stderr)
            return None
        return None
    except Exception as exc:
        print(f"External trace call failed: {exc}", file=sys.stderr)
        return None


def fetch_internal_txs_from_etherscan(
    tx_hash: str,
    etherscan_url: Optional[str],
    etherscan_key: Optional[str],
    timeout_sec: float = 10.0,
) -> Optional[List[Dict[str, Any]]]:
    """Fetch internal transactions for a tx via Etherscan API (txlistinternal)."""
    if not etherscan_url or not etherscan_key:
        return None

    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    url = f"{etherscan_url}?module=account&action=txlistinternal&txhash={tx_hash}&apikey={etherscan_key}"
    try:
        resp = requests.get(url, timeout=timeout_sec)
        if resp.status_code != 200:
            print(f"Etherscan HTTP {resp.status_code}", file=sys.stderr)
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("status") == "1" and data.get("result"):
            internal_txs = data["result"]
            traces: List[Dict[str, Any]] = []
            for itx in internal_txs:
                trace_item = {
                    "action": {
                        "from": itx.get("from", ""),
                        "to": itx.get("to", ""),
                        "value": str(itx.get("value", "0")),
                        "gas": str(itx.get("gas", "0")),
                        "input": itx.get("input", "0x"),
                    },
                    "result": {
                        "gasUsed": str(itx.get("gasUsed", "0")),
                    },
                    "type": itx.get("type", "call"),
                    "subtraces": 0,
                }
                if itx.get("type") == "create":
                    trace_item["result"]["address"] = itx.get("contractAddress", "")
                traces.append(trace_item)
            return traces
        else:
            # May return status "0" when no internal txs exist
            return None
    except Exception as exc:
        print(f"Etherscan internal tx fetch failed: {exc}", file=sys.stderr)
        return None


def fetch_tx_and_receipt_via_rpc(
    w3: Web3,
    tx_hash: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Fetch transaction and receipt via RPC. Returns (tx, receipt) as dicts if possible."""
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    tx_data: Optional[Dict[str, Any]] = None
    receipt_data: Optional[Dict[str, Any]] = None

    try:
        tx_obj = w3.eth.get_transaction(tx_hash)
        # web3 returns AttributeDict; convert to plain dict
        tx_data = dict(tx_obj) if hasattr(tx_obj, "items") else tx_obj
    except Exception as exc:
        print(f"RPC eth_getTransaction failed: {exc}", file=sys.stderr)

    try:
        receipt_obj = w3.eth.get_transaction_receipt(tx_hash)
        receipt_data = dict(receipt_obj) if hasattr(receipt_obj, "items") else receipt_obj
    except Exception as exc:
        print(f"RPC eth_getTransactionReceipt failed: {exc}", file=sys.stderr)

    return tx_data, receipt_data


def construct_basic_trace(
    tx_data: Optional[Dict[str, Any]],
    receipt_data: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Construct a simplified trace-like structure as a last resort."""
    if not tx_data and not receipt_data:
        return None

    from_addr = (tx_data or {}).get("from")
    to_addr = (tx_data or {}).get("to")
    value = str((tx_data or {}).get("value", 0))
    gas = str((tx_data or {}).get("gas", 0))
    input_data = (tx_data or {}).get("input", "0x")
    gas_used = str((receipt_data or {}).get("gasUsed", 0))

    basic = {
        "action": {
            "from": from_addr or "0x0000000000000000000000000000000000000000",
            "to": to_addr or "0x0000000000000000000000000000000000000000",
            "value": value,
            "gas": gas,
            "input": input_data,
        },
        "result": {"gasUsed": gas_used},
        "subtraces": len((receipt_data or {}).get("logs", [])) if isinstance((receipt_data or {}).get("logs"), list) else 0,
        "type": "call",
    }

    # contract creation case
    to_missing = receipt_data is not None and not receipt_data.get("to")
    if to_missing and receipt_data and receipt_data.get("contractAddress"):
        basic["type"] = "create"
        basic["result"]["address"] = receipt_data.get("contractAddress")

    return basic


def get_trace_for_tx(
    w3: Web3,
    tx_hash: str,
    trace_url: Optional[str],
    trace_api_key: Optional[str],
    etherscan_url: Optional[str],
    etherscan_key: Optional[str],
) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """Get trace for a transaction using a 3-step fallback strategy."""
    # 1) External service
    trace = fetch_trace_via_external_service(tx_hash, trace_url, trace_api_key)
    if trace is not None:
        shrink_trace_inputs(trace)
        return trace

    # 2) Etherscan internal txs
    internal = fetch_internal_txs_from_etherscan(tx_hash, etherscan_url, etherscan_key)
    if internal is not None:
        shrink_trace_inputs(internal)
        return internal

    # 3) Construct basic trace from RPC data
    tx_data, receipt_data = fetch_tx_and_receipt_via_rpc(w3, tx_hash)
    basic = construct_basic_trace(tx_data, receipt_data)
    if basic is not None:
        shrink_trace_inputs(basic)
    return basic


def run(attacker_address: str, start_block: int, end_block: int, rpc_url: str,
        trace_url: Optional[str], trace_api_key: Optional[str],
        etherscan_url: Optional[str], etherscan_key: Optional[str],
        sleep_between_traces_sec: float = 0.1,
        progress_interval: int = 0) -> Dict[str, Any]:
    """Main execution to scan and fetch traces for relevant transactions."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    transactions, tx_hashes = scan_relevant_transactions(
        w3=w3,
        attacker_address=attacker_address,
        start_block=start_block,
        end_block=end_block,
        progress_interval=progress_interval,
    )

    traces: Dict[str, Union[Dict[str, Any], List[Dict[str, Any]]]] = {}

    for tx_hash in tx_hashes:
        try:
            trace = get_trace_for_tx(
                w3=w3,
                tx_hash=tx_hash,
                trace_url=trace_url,
                trace_api_key=trace_api_key,
                etherscan_url=etherscan_url,
                etherscan_key=etherscan_key,
            )
            if trace is not None:
                traces[tx_hash] = trace
            time.sleep(sleep_between_traces_sec)
        except Exception as exc:
            print(f"Trace fetch failed for {tx_hash}: {exc}", file=sys.stderr)
            continue

    return {
        "attacker": attacker_address,
        "start_block": start_block,
        "end_block": end_block,
        "transaction_count": len(transactions),
        "trace_count": len(traces),
        "transactions": transactions,
        "traces": traces,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan attacker transactions and fetch traces over a block range.")
    parser.add_argument("attacker", type=str, help="Attacker address (0x...)")
    parser.add_argument("start", type=int, help="Start block")
    parser.add_argument("end", type=int, help="End block")

    parser.add_argument("--rpc-url", dest="rpc_url", type=str, default=os.getenv("RPC_URL", ""), help="Ethereum RPC URL")
    parser.add_argument("--trace-url", dest="trace_url", type=str, default=os.getenv("TRACE_URL", ""), help="External trace JSON-RPC URL (supports trace_transaction)")
    parser.add_argument("--trace-api-key", dest="trace_api_key", type=str, default=os.getenv("TRACE_API_KEY", ""), help="External trace API key (Bearer)")
    parser.add_argument("--etherscan-url", dest="etherscan_url", type=str, default=os.getenv("ETHERSCAN_URL", "https://api.etherscan.io/api"), help="Etherscan API base URL")
    parser.add_argument("--etherscan-key", dest="etherscan_key", type=str, default=os.getenv("ETHERSCAN_KEY", ""), help="Etherscan API key")
    parser.add_argument("--sleep", dest="sleep_sec", type=float, default=0.1, help="Sleep seconds between trace calls")
    parser.add_argument("--progress-interval", dest="progress_interval", type=int, default=0, help="打印扫描进度的区块间隔。0 表示不打印")

    parser.add_argument("--output", dest="output", type=str, default="", help="Output JSON file path (default: stdout)")

    args = parser.parse_args()
    if not args.rpc_url:
        raise SystemExit("RPC URL is required (use --rpc-url or set RPC_URL env var)")
    return args


def main() -> None:
    args = parse_args()
    result = run(
        attacker_address=args.attacker,
        start_block=args.start,
        end_block=args.end,
        rpc_url=args.rpc_url,
        trace_url=args.trace_url or None,
        trace_api_key=args.trace_api_key or None,
        etherscan_url=args.etherscan_url or None,
        etherscan_key=args.etherscan_key or None,
        sleep_between_traces_sec=args.sleep_sec,
        progress_interval=args.progress_interval,
    )

    output_str = json.dumps(result, ensure_ascii=False, indent=2, default=json_default)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Wrote output to {args.output}")
    else:
        print(output_str)


if __name__ == "__main__":
    main() 