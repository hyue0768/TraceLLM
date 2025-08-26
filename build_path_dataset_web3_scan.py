#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于Web3区块扫描的路径级数据集构建脚本

参考main.py的实现：
1. 使用Web3扫描区块获取交易列表
2. 使用Ankr API获取trace数据
"""

import os
import sys
import json
import pandas as pd
import hashlib
import requests
import time
import traceback
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import logging
from web3 import Web3
from tqdm import tqdm
import openpyxl  # 用于Excel文件处理

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('path_extraction_web3_scan.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class Web3BlockchainScanner:
    """基于Web3的区块链扫描器，参考main.py和analyze_user_behavior.py实现"""
    
    def __init__(self):
        # 导入设置模块
        try:
            sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
            from config.settings import settings
            self.settings = settings
        except ImportError:
            logger.error("❌ 无法导入配置模块，请检查路径")
            raise
        
        # 获取网络配置
        self.network = "ethereum"
        self.network_config = self.settings.NETWORKS[self.network]
        
        # 初始化Web3连接（用于区块扫描）
        self.rpc_url = self.network_config.get("rpc_url", "https://ethereum.publicnode.com")
        
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if self.w3.is_connected():
                logger.info(f"✅ 成功连接到以太坊节点: {self.rpc_url}")
                latest_block = self.w3.eth.block_number
                logger.info(f"📊 当前最新区块: {latest_block}")
            else:
                raise Exception("Web3连接失败")
        except Exception as e:
            logger.error(f"❌ Web3连接失败: {str(e)}")
            # 尝试公共节点作为备用
            try:
                self.rpc_url = "https://ethereum.publicnode.com"
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                if self.w3.is_connected():
                    logger.info(f"✅ 使用备用公共节点连接成功: {self.rpc_url}")
                else:
                    raise Exception("备用节点也连接失败")
            except Exception as e2:
                logger.error(f"❌ 备用节点连接也失败: {str(e2)}")
                self.w3 = None
            
        # Trace服务配置（完全参考analyze_user_behavior.py）
        self.trace_url = self.network_config.get('trace_url', self.rpc_url)
        self.trace_api_key = self.network_config.get('trace_api_key') or os.getenv('ANKR_API_KEY')
        self.use_local_node = self.network_config.get('use_local_node', False)
        
        # 检查是否有外部API可用
        self.has_external_api = bool(self.trace_api_key) or self.trace_url != self.rpc_url
        
        logger.info(f"🔧 网络配置:")
        logger.info(f"  - RPC URL: {self.rpc_url}")
        logger.info(f"  - Trace URL: {self.trace_url}")
        logger.info(f"  - 有外部API: {self.has_external_api}")
        logger.info(f"  - 使用本地节点: {self.use_local_node}")
        
        if not self.trace_api_key and not self.has_external_api:
            logger.warning("⚠️ 未配置外部trace API，可能影响trace质量")

    def scan_blocks_for_transactions(self, target_address: str, start_block: int, end_block: int) -> List[Dict]:
        """
        扫描区块范围，找到与目标地址相关的所有交易
        完全参考main.py中的_analyze_contract_hybrid_mode实现
        
        Args:
            target_address (str): 目标地址（攻击者地址）
            start_block (int): 开始区块
            end_block (int): 结束区块
            
        Returns:
            List[Dict]: 相关交易列表
        """
        if not self.w3:
            logger.error("❌ Web3连接不可用")
            return []
            
        logger.info(f"🔍 扫描地址 {target_address} 在区块 {start_block}-{end_block} 范围内的交易")
        
        target_address_lower = target_address.lower()
        relevant_transactions = []
        
        try:
            # 使用tqdm显示进度，完全参考main.py
            for block_num in tqdm(range(start_block, end_block + 1), desc="扫描区块"):
                try:
                    # 获取完整区块信息（包含所有交易）
                    block = self.w3.eth.get_block(block_num, full_transactions=True)
                    
                    for tx in block.transactions:
                        try:
                            # 检查交易是否与目标地址相关
                            tx_from = tx.get('from', '').lower() if tx.get('from') else ''
                            tx_to = tx.get('to', '').lower() if tx.get('to') else ''
                            
                            # 检查是否为目标地址相关的交易
                            is_target_sender = tx_from == target_address_lower
                            is_target_recipient = tx_to == target_address_lower
                            is_contract_creation = tx.to is None and is_target_sender  # 合约创建
                            
                            if is_target_sender or is_target_recipient or is_contract_creation:
                                tx_hash = tx.hash.hex() if isinstance(tx.hash, bytes) else str(tx.hash)
                                
                                # 解析input data获取method name
                                input_data = tx.input.hex() if isinstance(tx.input, bytes) else str(tx.input)
                                method_name = 'unknown'
                                if input_data and len(input_data) >= 10:
                                    method_id = input_data[:10]
                                    method_name = lookup_method_from_4byte(method_id)
                                elif not input_data or input_data == '0x':
                                    method_name = 'eth_transfer'
                                
                                tx_data = {
                                    'tx_hash': tx_hash,
                                    'block_number': block_num,
                                    'from_address': tx_from,
                                    'to_address': tx_to,
                                    'method_name': method_name,
                                    'input_data': input_data,
                                    'value': str(tx.value),
                                    'gas': str(tx.gas),
                                    'gas_price': str(tx.gasPrice),
                                    'timestamp': datetime.fromtimestamp(block.timestamp),
                                    'is_contract_creation': is_contract_creation,
                                    'transaction_index': tx.transactionIndex
                                }
                                
                                # 如果是合约创建，尝试获取创建的合约地址
                                if is_contract_creation:
                                    try:
                                        receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                                        if receipt and receipt.get('contractAddress'):
                                            created_address = receipt['contractAddress'].lower()
                                            tx_data['created_contract_address'] = created_address
                                            logger.info(f"发现创建的合约地址: {created_address}")
                                    except Exception as e:
                                        logger.warning(f"获取合约创建地址失败: {str(e)}")
                                
                                relevant_transactions.append(tx_data)
                                logger.info(f"找到相关交易: {tx_hash} (块: {block_num})")
                                
                        except Exception as e:
                            logger.warning(f"处理交易时出错: {str(e)}")
                            continue
                            
                except Exception as e:
                    logger.warning(f"获取区块 {block_num} 时出错: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.error(f"扫描区块时出错: {str(e)}")
            
        logger.info(f"✅ 扫描完成，找到 {len(relevant_transactions)} 笔相关交易")
        return relevant_transactions



    def get_transaction_trace(self, tx_hash: str) -> Optional[List[Dict]]:
        """
        获取交易的完整调用追踪，完全参考analyze_user_behavior.py实现
        
        Args:
            tx_hash (str): 交易哈希
            
        Returns:
            List[Dict]: trace数据
        """
        # 确保tx_hash格式正确
        if isinstance(tx_hash, bytes):
            tx_hash = tx_hash.hex()
        
        if not tx_hash.startswith('0x'):
            tx_hash = '0x' + tx_hash
        
        try:
            logger.info(f"🔍 获取交易 {tx_hash} 的trace数据")
            
            # 检查是否使用本地节点，优先使用外部API
            use_local_node = self.use_local_node
            trace_url = self.trace_url
            
            # 如果有外部API可用，强制使用外部API
            if self.has_external_api:
                logger.info(f"使用外部API获取交易 {tx_hash} 的跟踪信息...")
                use_local_node = False
                trace_url = self.trace_url
            elif use_local_node:
                logger.info(f"使用本地节点获取交易 {tx_hash} 的跟踪信息...")
            else:
                logger.info(f"使用外部节点获取交易 {tx_hash} 的跟踪信息...")
            
            # 构建请求负载
            payload = {
                "jsonrpc": "2.0",
                "method": "trace_transaction",
                "params": [tx_hash],
                "id": 1
            }
            
            # 添加认证头部
            headers = {
                "Content-Type": "application/json"
            }
            
            # 只有在使用外部节点时才添加API密钥
            if not use_local_node and self.trace_api_key:
                headers["Authorization"] = f"Bearer {self.trace_api_key}"
            
            # 添加重试机制和错误处理
            max_retries = 3
            retry_delay = 2
            
            for attempt in range(max_retries):
                try:
                    # 发送请求
                    response = requests.post(
                        trace_url,
                        headers=headers,
                        json=payload,
                        timeout=30  # 设置30秒超时
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if 'result' in result and result['result'] is not None:
                            logger.info(f"✅ 成功获取交易 {tx_hash} 的跟踪信息")
                            trace_data = result['result']
                            logger.info(f"预览trace数据: {str(trace_data)[:200]}...")  # 仅显示前200个字符
                            return trace_data
                        elif 'error' in result:
                            error_msg = result['error'].get('message', '未知错误')
                            logger.warning(f"获取跟踪信息失败: {error_msg}")
                            
                            # 如果是本地节点且不支持trace_transaction，尝试其他方法
                            if use_local_node and ('method not found' in error_msg.lower() or 'not supported' in error_msg.lower()):
                                logger.info("本地节点不支持trace_transaction方法，使用备用方法...")
                                return self._get_transaction_trace_alternative(tx_hash)
                            
                            # 检查是否是格式错误，如果是，可以尝试调整格式后重试
                            if 'invalid argument' in error_msg.lower():
                                # 尝试不同的哈希格式
                                if attempt == 0:
                                    logger.info("尝试使用不同的哈希格式...")
                                    if payload["params"][0].startswith("0x"):
                                        payload["params"][0] = payload["params"][0][2:]
                                    else:
                                        payload["params"][0] = "0x" + payload["params"][0]
                                    continue
                            
                            # 如果不是格式错误或者已经尝试过不同格式，使用备用方法
                            return self._get_transaction_trace_alternative(tx_hash)
                        else:
                            logger.warning("API返回了空结果")
                            return self._get_transaction_trace_alternative(tx_hash)
                    else:
                        logger.warning(f"请求失败，状态码: {response.status_code}")
                        logger.warning(f"响应内容: {response.text[:500]}...")
                        if attempt < max_retries - 1:
                            logger.info(f"将在 {retry_delay} 秒后重试...")
                            time.sleep(retry_delay)
                        else:
                            # 最后一次尝试失败，使用备用方法
                            return self._get_transaction_trace_alternative(tx_hash)
                
                except requests.exceptions.Timeout:
                    logger.warning(f"请求超时 (尝试 {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        logger.info(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    else:
                        # 最后一次尝试也超时，使用备用方法
                        return self._get_transaction_trace_alternative(tx_hash)
                        
                except Exception as e:
                    logger.warning(f"获取交易跟踪时出错: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    else:
                        # 最后一次尝试也失败，使用备用方法
                        return self._get_transaction_trace_alternative(tx_hash)
            
            # 所有重试都失败
            return None
                
        except Exception as e:
            logger.error(f"获取交易跟踪时出错: {str(e)}")
            traceback.print_exc()
            return None

    def _get_transaction_trace_alternative(self, tx_hash: str) -> Optional[Dict]:
        """
        当trace_transaction API调用失败时的备用方法，使用交易收据获取基本信息
        完全参考analyze_user_behavior.py实现
        """
        logger.info(f"使用备用方法获取交易 {tx_hash} 的信息...")
        
        try:
            # 确保tx_hash格式正确
            if not tx_hash.startswith('0x'):
                tx_hash = '0x' + tx_hash
                
            # 获取交易收据
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            if not receipt:
                logger.warning("无法获取交易收据")
                return None
                
            # 尝试获取交易详情，如果失败则使用收据中的信息
            tx_data = None
            try:
                tx_data = self.w3.eth.get_transaction(tx_hash)
            except Exception as tx_error:
                logger.warning(f"获取交易详情失败（可能节点不支持eth_getTransaction）: {str(tx_error)}")
                logger.info("将仅使用交易收据信息构建trace")
                
            # 构建简化的trace结构
            trace = {
                "action": {
                    "from": receipt['from'],
                    "to": receipt.get('to', '0x0000000000000000000000000000000000000000'),
                    "value": str(tx_data.get('value', 0)) if tx_data else "0",
                    "gas": str(tx_data.get('gas', receipt.get('gasUsed', 0))) if tx_data else str(receipt.get('gasUsed', 0)),
                    "input": tx_data.get('input', '0x') if tx_data else '0x'
                },
                "result": {
                    "gasUsed": str(receipt.get('gasUsed', 0)),
                    "status": "0x1" if receipt.get('status') == 1 else "0x0"
                },
                "subtraces": len(receipt.get('logs', [])),
                "type": "call"
            }
            
            # 如果是合约创建交易
            if not receipt.get('to'):
                trace["type"] = "create"
                trace["result"]["address"] = receipt.get('contractAddress')
                
            # 处理日志作为内部调用
            if receipt.get('logs'):
                calls = []
                for log in receipt.get('logs', []):
                    calls.append({
                        "action": {
                            "from": receipt['from'],
                            "to": log['address'],
                            "input": "0x" + log['topics'][0][2:] if log['topics'] else "0x",
                            "gas": "0"
                        },
                        "result": {
                            "gasUsed": "0"
                        },
                        "type": "call"
                    })
                trace["calls"] = calls
                
            logger.info(f"✅ 成功创建备用trace结构")
            return trace
                
        except Exception as e:
            logger.error(f"备用方法失败: {str(e)}")
            traceback.print_exc()
            return None

def process_trace_to_call_hierarchy(trace_data, scanner: Web3BlockchainScanner, tx_info: Dict) -> Dict:
    """
    将raw trace数据处理为调用层次结构，然后使用analyze_user_behavior.py的方法重建
    完全参考analyze_user_behavior.py的处理流程
    """
    try:
        logger.info(f"🔄 开始处理交易 {tx_info['tx_hash']} 的trace数据")
        
        # 步骤1: 创建原始调用层次结构
        method_name = tx_info.get('method_name', 'unknown')
        method_id = tx_info.get('input_data', '0x')[:10] if tx_info.get('input_data') else "0x"
        
        # 如果method_name不准确，使用4byte目录查找
        if method_name in ['unknown', '_SIMONdotBLACK_', 'workMyDirefulOwner'] or method_name.startswith('0x'):
            try:
                corrected_method = lookup_method_from_4byte(method_id)
                if corrected_method and corrected_method != method_name:
                    logger.info(f"🔧 修正函数名: {method_name} -> {corrected_method}")
                    method_name = corrected_method
            except Exception as e:
                logger.warning(f"重新解析函数名失败: {str(e)}")
        
        root_node = {
            'from': tx_info['from_address'],
            'to': tx_info['to_address'],
            'method': method_name,
            'method_id': method_id,
            'input': tx_info.get('input_data', '0x'),
            'value': tx_info.get('value', '0'),
            'call_type': 'root',
            'children': []
        }
        
        # 收集相关合约地址
        related_contracts = set()
        
        # 处理trace以构建初始调用层次结构
        call_path = [tx_info['to_address']]
        process_trace_without_db_checks(
            trace_data, 
            root_node, 
            related_contracts,
            call_path,
            0,
            max_depth=5  # 设置最大深度
        )
        
        # 步骤2: 从调用层次结构提取扁平化调用列表（参考analyze_user_behavior.py）
        flat_calls = extract_flat_calls_from_hierarchy_local(root_node)
        logger.info(f"✅ 提取到 {len(flat_calls)} 个扁平化调用")
        
        # 步骤3: 使用analyze_user_behavior.py的逻辑重建调用层次结构
        if flat_calls:
            rebuilt_hierarchy = rebuild_call_hierarchy_with_depth_local(flat_calls)
            if rebuilt_hierarchy:
                logger.info(f"✅ 成功重建调用层次结构")
                return rebuilt_hierarchy
            else:
                logger.warning(f"⚠️ 重建失败，返回原始层次结构")
                return root_node
        else:
            logger.warning(f"⚠️ 没有扁平化调用，返回原始层次结构")
            return root_node
        
    except Exception as e:
        logger.error(f"❌ 处理trace数据时出错: {str(e)}")
        traceback.print_exc()
        return None

def extract_flat_calls_from_hierarchy_local(call_hierarchy):
    """
    从call_hierarchy中提取扁平化的调用列表
    完全参考analyze_user_behavior.py的extract_flat_calls_from_hierarchy实现
    
    Args:
        call_hierarchy: 原始的调用层次结构
        
    Returns:
        list: 扁平化的调用列表
    """
    if not call_hierarchy:
        return []
    
    flat_calls = []
    
    def traverse_hierarchy(node):
        """递归遍历调用层次结构"""
        if not node or not isinstance(node, dict):
            return
        
        # 添加当前节点到扁平列表
        call_item = {
            'from': node.get('from'),
            'to': node.get('to'),
            'method': node.get('method', node.get('method_id', '')),
            'value': node.get('value', '0')
        }
        
        # 只有当from和to都存在时才添加
        if call_item['from'] and call_item['to']:
            flat_calls.append(call_item)
        
        # 递归处理子节点
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                traverse_hierarchy(child)
    
    # 开始遍历
    traverse_hierarchy(call_hierarchy)
    
    return flat_calls

def rebuild_call_hierarchy_with_depth_local(flat_calls):
    """
    从扁平化的调用列表重建调用树结构，基于严格的新嵌套逻辑
    完全参考analyze_user_behavior.py的rebuild_call_hierarchy_with_depth实现
    
    严格新规则：
    - call[i] 是 call[i-1] 的子调用 ⟺ call[i].from == call[i-1].to
    - 如果满足子调用条件，且 call[i+1].from == call[i].from，则 call[i+1] 是 call[i] 的平级节点
    - 平级关系可以递归向后扩展，直到出现 call[j].from != call[j-1].from
    - 如果 call[i].from != call[i-1].to，则 call[i] 必须是新调用树的根节点（不再寻找之前的父节点）
    
    Args:
        flat_calls (list): 扁平化的调用列表，每个调用包含 from, to, method, value等字段
        
    Returns:
        dict: 重建后的调用树，包含depth字段和正确的children层次结构
    """
    if not flat_calls or not isinstance(flat_calls, list):
        return None
    
    if len(flat_calls) == 0:
        return None
    
    def create_node(call, index, depth=0):
        """创建调用节点"""
        node = {
            'from': call.get('from'),
            'to': call.get('to'),
            'method': call.get('method'),
            'value': call.get('value', '0'),
            'children': [],
            'depth': depth,
            'call_index': index,
            'call_type': 'function_call'
        }
        
        # 添加调用类型分析
        method = node.get('method', '')
        if 'mint' in method.lower():
            node['call_type'] = 'mint_operation'
        elif 'swap' in method.lower():
            node['call_type'] = 'swap_operation'
        elif 'transfer' in method.lower():
            node['call_type'] = 'transfer_operation'
        elif 'approve' in method.lower():
            node['call_type'] = 'approval_operation'
        elif 'callback' in method.lower():
            node['call_type'] = 'callback'
        elif method.startswith('0x'):
            node['call_type'] = 'function_call'
        else:
            node['call_type'] = 'function_call'
        
        return node
    
    # 构建所有的树
    trees = []
    current_parent = None
    
    i = 0
    while i < len(flat_calls):
        call = flat_calls[i]
        
        # 第一个调用总是根节点
        if i == 0:
            root_node = create_node(call, i, depth=0)
            trees.append(root_node)
            current_parent = root_node
            i += 1
            continue
        
        prev_call = flat_calls[i-1]
        
        # 检查是否是子调用：call[i].from == call[i-1].to
        if call.get('from', '').lower() == prev_call.get('to', '').lower():
            # 是子调用，深度 = 父节点深度 + 1
            child_depth = current_parent['depth'] + 1
            
            # 收集所有平级节点：相同 from 地址的连续调用
            sibling_calls = []
            j = i
            while j < len(flat_calls):
                current_call = flat_calls[j]
                if current_call.get('from', '').lower() == call.get('from', '').lower():
                    sibling_calls.append((current_call, j))
                    j += 1
                else:
                    break
            
            # 为所有平级节点创建节点并添加到当前父节点
            for sibling_call, call_index in sibling_calls:
                sibling_node = create_node(sibling_call, call_index, child_depth)
                current_parent['children'].append(sibling_node)
            
            # 更新当前父节点为最后一个兄弟节点（用于下一层的子调用）
            if sibling_calls:
                current_parent = current_parent['children'][-1]
            
            # 跳过已处理的平级节点
            i = j
            continue
        
        else:
            # 不是子调用，必须是新树的根节点
            root_node = create_node(call, i, depth=0)
            trees.append(root_node)
            current_parent = root_node
            i += 1
    
    # 返回结果
    if len(trees) == 1:
        return trees[0]
    elif len(trees) > 1:
        # 创建虚拟根节点包含所有树
        virtual_root = {
            'from': 'virtual_root',
            'to': 'virtual_root',
            'method': 'virtual_root',
            'value': '0',
            'children': trees,
            'depth': -1,
            'call_index': -1,
            'call_type': 'virtual_root'
        }
        
        # 调整所有树的深度
        def adjust_depth(node, depth_offset):
            node['depth'] += depth_offset
            for child in node.get('children', []):
                adjust_depth(child, depth_offset)
        
        for tree in trees:
            adjust_depth(tree, 1)
        
        return virtual_root
    else:
        return None

def process_trace_without_db_checks(trace, parent_node, related_contracts, call_path, current_depth, max_depth=5):
    """
    处理trace数据以构建调用层次结构，避免数据库查询
    完全参考analyze_user_behavior.py的实现
    """
    if current_depth >= max_depth:
        return
    
    try:
        # 处理单个trace格式
        if isinstance(trace, dict):
            # 新的trace结构 (trace_transaction 格式)
            if 'action' in trace:
                process_trace_action_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth)
            # 旧格式
            elif 'from' in trace and 'to' in trace:
                process_trace_old_format_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth)
        
        # 处理trace列表
        elif isinstance(trace, list):
            for subtrace in trace:
                process_trace_without_db_checks(subtrace, parent_node, related_contracts, call_path, current_depth, max_depth)
    
    except Exception as e:
        logger.warning(f"递归处理trace时出错：{str(e)}")

def process_trace_action_without_db(call, parent_node, related_contracts, call_path, current_depth, max_depth):
    """
    处理action格式的trace，避免数据库查询
    完全参考analyze_user_behavior.py的实现
    """
    try:
        action = call['action']
        from_address = action.get('from', '').lower() if action.get('from') else ''
        to_address = action.get('to', '').lower() if action.get('to') else ''
        input_data = action.get('input', '0x')
        call_type = action.get('callType', 'call')
        value = action.get('value', '0x0')
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        logger.debug(f"处理trace: from={from_address}({has_from}), to={to_address}({has_to}), type={call_type}")
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 尝试提取方法ID和解析函数名
            method_id = "0x"
            method_name = "unknown"
            if input_data and len(input_data) >= 10:
                method_id = input_data[:10]
                
                # 尝试解析函数名
                try:
                    # 直接使用4byte目录查找
                    parsed_method = lookup_method_from_4byte(method_id)
                    if parsed_method:
                        method_name = parsed_method
                    else:
                        method_name = 'method_id'
                except Exception:
                    method_name = 'method_id'
            else:
                # 对于ETH转账或合约创建，使用更明确的标识
                if not input_data or input_data == '0x':
                    method_name = "eth_transfer"
                else:
                    method_name = "contract_creation"
            
            # 创建调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method': method_name,
                'method_id': method_id,
                'call_type': call_type,
                'value': value,
                'input': input_data,
                'depth': current_depth + 1,
                'children': []
            }
            
            # 添加到父节点
            parent_node['children'].append(call_node)
            
            # 构建新调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'subtraces' in call and call['subtraces'] > 0:
                if 'calls' in call and isinstance(call['calls'], list):
                    for subcall in call['calls']:
                        process_trace_without_db_checks(
                            subcall, 
                            call_node,
                            related_contracts, 
                            new_call_path,
                            current_depth + 1, 
                            max_depth
                        )
    except Exception as e:
        logger.warning(f"处理trace action时出错: {str(e)}")

def process_trace_old_format_without_db(trace, parent_node, related_contracts, call_path, current_depth, max_depth):
    """
    处理旧格式的trace，避免数据库查询
    完全参考analyze_user_behavior.py的实现
    """
    try:
        from_address = trace.get('from', '').lower() if trace.get('from') else ''
        to_address = trace.get('to', '').lower() if trace.get('to') else ''
        
        # 检查地址是否有效
        has_from = bool(from_address and Web3.is_address(from_address))
        has_to = bool(to_address and Web3.is_address(to_address))
        
        if has_from or has_to:
            # 将有效地址添加到相关合约集合
            if has_from:
                related_contracts.add(from_address)
            if has_to:
                related_contracts.add(to_address)
            
            # 解析方法名
            method_id = trace.get('method_id', '0x')
            method_name = "unknown"
            if method_id and method_id != '0x':
                try:
                    parsed_method = lookup_method_from_4byte(method_id)
                    if parsed_method:
                        method_name = parsed_method
                    else:
                        method_name = 'method_id'
                except Exception:
                    method_name = 'method_id'
            else:
                method_name = "eth_transfer"
            
            # 创建调用节点
            call_node = {
                'from': from_address if has_from else "unknown",
                'to': to_address if has_to else "unknown",
                'method': method_name,
                'method_id': method_id,
                'call_type': trace.get('type', 'call'),
                'value': trace.get('value', '0x0'),
                'depth': current_depth + 1,
                'children': []
            }
            
            # 添加到父节点
            parent_node['children'].append(call_node)
            
            # 构建新调用路径
            new_call_path = call_path
            if has_to:
                new_call_path = call_path + [to_address]
            
            # 递归处理子trace
            if 'children' in trace and isinstance(trace['children'], list):
                for child in trace['children']:
                    process_trace_without_db_checks(
                        child,
                        call_node,
                        related_contracts,
                        new_call_path,
                        current_depth + 1,
                        max_depth
                    )
    except Exception as e:
        logger.warning(f"处理旧格式trace时出错: {str(e)}")

def lookup_method_from_4byte(selector):
    """从4-byte选择器数据库查询方法签名，参考analyze_user_behavior.py实现"""
    try:
        if not selector or selector == '0x' or len(selector) != 10:
            return "contract_creation_or_eth_transfer"
        
        hex_method_id = selector if selector.startswith('0x') else f'0x{selector}'
        
        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={hex_method_id}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        if data and data.get('results'):
            results = sorted(data['results'], key=lambda x: x['id'])
            return results[0]['text_signature']
            
        return f"{selector}"
        
    except Exception:
        return f"lookup_error({selector})"

def extract_all_paths_from_call_tree(call_hierarchy: Dict) -> List[List[Dict]]:
    """
    使用DFS从调用树中提取所有从根到叶的执行路径
    完全参考analyze_user_behavior.py的DFS实现，处理重建后的调用层次结构
    """
    all_paths = []
    
    def dfs(node, current_path=None, depth=0):
        """深度优先搜索遍历调用树"""
        if current_path is None:
            current_path = []
        
        # 创建当前节点的路径信息
        node_info = {
            'from': node.get('from', ''),
            'to': node.get('to', ''),
            'method': node.get('method', ''),
            'method_id': node.get('method_id', ''),
            'value': node.get('value', '0'),
            'depth': node.get('depth', depth),  # 使用重建后的depth字段
            'call_type': node.get('call_type', 'function_call'),
            'input': node.get('input', ''),
            'address': node.get('to', '').lower(),  # 当前调用的目标地址
            'call_index': node.get('call_index', -1)  # 添加调用索引
        }
        
        # 将当前节点添加到路径
        new_path = current_path + [node_info]
        
        # 获取子节点
        children = node.get('children', [])
        
        if not children:
            # 叶节点，保存完整路径
            all_paths.append(new_path.copy())
            logger.debug(f"✅ 发现叶节点路径，长度: {len(new_path)}, 最大深度: {node_info['depth']}")
        else:
            # 递归处理每个子节点
            for child in children:
                dfs(child, new_path, depth + 1)
    
    # 从根节点开始DFS
    if call_hierarchy:
        # 检查是否是虚拟根节点
        if call_hierarchy.get('method') == 'virtual_root':
            logger.info(f"🔄 检测到虚拟根节点，遍历所有子树...")
            for child_tree in call_hierarchy.get('children', []):
                logger.info(f"🔄 遍历子树: {child_tree.get('from', 'unknown')} -> {child_tree.get('to', 'unknown')}")
                dfs(child_tree, [], 0)
        else:
            logger.info(f"🔄 开始DFS遍历调用树，根节点: {call_hierarchy.get('from', 'unknown')} -> {call_hierarchy.get('to', 'unknown')}")
            dfs(call_hierarchy, [], 0)
        
        logger.info(f"✅ DFS完成，提取到 {len(all_paths)} 条执行路径")
    else:
        logger.warning("❌ 调用层次结构为空，无法提取路径")
    
    return all_paths

def read_security_events(excel_file: str, max_rows: int = None) -> List[Dict]:
    """读取Excel文件中的安全事件数据"""
    try:
        df = pd.read_excel(excel_file)
        
        if max_rows:
            df = df.head(max_rows)
        
        events = []
        for index, row in df.iterrows():
            if pd.notna(row.get('Address')) and pd.notna(row.get('Blockstart')) and pd.notna(row.get('Blockend')):
                event = {
                    'event_id': f'event_{index+1}',
                    'name': row.get('Name', f'Event_{index+1}'),
                    'address': str(row['Address']).strip().lower(),
                    'blockstart': int(row['Blockstart']),
                    'blockend': int(row['Blockend']),
                    'type': row.get('Type', 'Unknown'),
                    'date': row.get('Date', 'Unknown'),
                }
                events.append(event)
        
        logger.info(f"成功读取 {len(events)} 个安全事件")
        return events
    
    except Exception as e:
        logger.error(f"读取Excel文件时出错: {str(e)}")
        return []

def extract_path_features(path: List[Dict], tx_hash: str, event_info: Dict, tx_info: Dict) -> Dict:
    """从路径中提取特征信息"""
    if not path:
        return {}
    
    # 生成路径唯一ID
    path_content = "->".join([f"{node['from'][:10]}:{node['to'][:10]}:{node['method']}" for node in path])
    path_id = hashlib.md5(f"{tx_hash}_{path_content}".encode()).hexdigest()[:16]
    
    # 提取所有方法名
    methods = [node['method'] for node in path if node['method']]
    unique_methods = list(set(methods))
    
    # 提取所有地址
    addresses = set()
    for node in path:
        if node['from'] and node['from'] != 'unknown':
            addresses.add(node['from'])
        if node['to'] and node['to'] != 'unknown':
            addresses.add(node['to'])
    unique_addresses = list(addresses)
    
    # 计算路径深度
    max_depth = max([node['depth'] for node in path]) if path else 0
    
    # 计算路径中的价值转移
    total_value = 0
    for node in path:
        try:
            value = node['value']
            if isinstance(value, str):
                if value.startswith('0x'):
                    total_value += int(value, 16)
                elif value.isdigit():
                    total_value += int(value)
        except:
            pass
    
    # 分析调用类型分布
    call_types = [node['call_type'] for node in path]
    call_type_counts = {ct: call_types.count(ct) for ct in set(call_types)}
    
    # 构建路径的详细内容（包含每个节点的信息）
    path_nodes_detail = []
    for i, node in enumerate(path):
        node_detail = {
            'step': i + 1,
            'from': node['from'],
            'to': node['to'],
            'method': node['method'],
            'method_id': node['method_id'],
            'depth': node['depth'],
            'call_type': node['call_type'],
            'value': node['value'],
            'input': node['input']
        }
        path_nodes_detail.append(node_detail)
    
    return {
        'path_id': path_id,
        'event_id': event_info['event_id'],
        'event_name': event_info['name'],
        'attacker_address': event_info['address'],
        'tx_hash': tx_hash,
        'tx_block_number': tx_info['block_number'],
        'tx_method_name': tx_info['method_name'],
        'path_length': len(path),
        'max_depth': max_depth,
        'path_content': path_content,
        'methods': methods,
        'unique_methods': unique_methods,
        'method_count': len(unique_methods),
        'addresses': unique_addresses,
        'address_count': len(unique_addresses),
        'total_value': total_value,
        'call_type_distribution': call_type_counts,
        'contains_create': any('create' in node['call_type'] for node in path),
        'contains_transfer': any('transfer' in node['method'].lower() for node in path),
        'contains_swap': any('swap' in node['method'].lower() for node in path),
        'contains_approve': any('approve' in node['method'].lower() for node in path),
        'block_range_start': event_info['blockstart'],
        'block_range_end': event_info['blockend'],
        'event_type': event_info['type'],
        'path_nodes_detail': path_nodes_detail,  # 新增：详细的路径节点信息
        'extraction_timestamp': datetime.now().isoformat()
    }

def process_single_event(event: Dict, scanner: Web3BlockchainScanner, max_transactions: int = None) -> List[Dict]:
    """处理单个安全事件，通过Web3扫描区块获取交易"""
    logger.info(f"开始处理事件: {event['name']} (攻击者: {event['address']})")
    
    # 通过Web3扫描区块获取相关交易
    transactions = scanner.scan_blocks_for_transactions(
        event['address'], 
        event['blockstart'], 
        event['blockend']
    )
    
    if not transactions:
        logger.warning(f"事件 {event['name']} 没有找到相关交易")
        return []
    
    # 限制处理的交易数量
    if max_transactions:
        transactions = transactions[:max_transactions]
        logger.info(f"限制处理交易数量为: {max_transactions}")
    
    all_path_features = []
    
    for i, tx in enumerate(transactions, 1):
        try:
            logger.info(f"🔄 处理交易 {i}/{len(transactions)}: {tx['tx_hash']}")
            
            # 获取trace数据
            trace_data = scanner.get_transaction_trace(tx['tx_hash'])
            
            if not trace_data:
                logger.warning(f"❌ 交易 {tx['tx_hash']} 无法获取trace数据")
                continue
            
            # 将raw trace处理为调用层次结构
            call_hierarchy = process_trace_to_call_hierarchy(trace_data, scanner, tx)
            
            if not call_hierarchy:
                logger.warning(f"❌ 交易 {tx['tx_hash']} 无法构建调用层次结构")
                continue
            
            # 提取所有执行路径
            all_paths = extract_all_paths_from_call_tree(call_hierarchy)
            
            logger.info(f"✅ 交易 {tx['tx_hash']} 提取到 {len(all_paths)} 条执行路径")
            
            # 为每条路径提取特征
            for path_idx, path in enumerate(all_paths, 1):
                if path:
                    logger.debug(f"处理路径 {path_idx}/{len(all_paths)}: {' -> '.join([node.get('to', 'unknown') for node in path])}")
                    path_features = extract_path_features(path, tx['tx_hash'], event, tx)
                    if path_features:
                        all_path_features.append(path_features)
        
        except Exception as e:
            logger.error(f"❌ 处理交易 {tx['tx_hash']} 时出错: {str(e)}")
            traceback.print_exc()
            continue
    
    logger.info(f"🎯 事件 {event['name']} 总共提取到 {len(all_path_features)} 条路径")
    return all_path_features

def save_event_dataset(path_features: List[Dict], event_info: Dict, output_format: str = 'csv', output_dir: str = 'path_datasets') -> str:
    """为单个事件保存路径数据集"""
    Path(output_dir).mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # 使用事件名称和地址创建更具描述性的文件名
    safe_event_name = "".join(c for c in event_info['name'] if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_event_name = safe_event_name.replace(' ', '_')[:50]  # 限制长度
    event_address_short = event_info['address'][:10]  # 地址前10个字符
    
    filename = f"event_{event_info['event_id']}_{safe_event_name}_{event_address_short}_{timestamp}"
    
    if not path_features:
        logger.warning(f"事件 {event_info['name']} 没有路径特征数据可保存")
        return ""
    
    # 转换为DataFrame
    df = pd.DataFrame(path_features)
    
    # 展开嵌套的列表字段
    df['methods_str'] = df['methods'].apply(lambda x: '|'.join(x) if x else '')
    df['unique_methods_str'] = df['unique_methods'].apply(lambda x: '|'.join(x) if x else '')
    df['addresses_str'] = df['addresses'].apply(lambda x: '|'.join(x) if x else '')
    df['call_type_distribution_str'] = df['call_type_distribution'].apply(lambda x: json.dumps(x) if x else '{}')
    df['path_nodes_detail_str'] = df['path_nodes_detail'].apply(lambda x: json.dumps(x) if x else '[]')
    
    # 移除原始的列表字段
    df_save = df.drop(['methods', 'unique_methods', 'addresses', 'call_type_distribution', 'path_nodes_detail'], axis=1)
    
    try:
        if output_format.lower() == 'csv':
            output_path = os.path.join(output_dir, f"{filename}.csv")
            df_save.to_csv(output_path, index=False, encoding='utf-8')
        elif output_format.lower() == 'excel':
            output_path = os.path.join(output_dir, f"{filename}.xlsx")
            df_save.to_excel(output_path, index=False, engine='openpyxl')
        elif output_format.lower() == 'parquet':
            output_path = os.path.join(output_dir, f"{filename}.parquet")
            df_save.to_parquet(output_path, index=False)
        else:
            raise ValueError(f"不支持的输出格式: {output_format}")
        
        logger.info(f"📁 事件 {event_info['name']} 数据集已保存到: {output_path}")
        logger.info(f"📊 数据集包含 {len(df_save)} 条路径记录")
        
        # 打印统计信息
        logger.info(f"📈 事件 {event_info['name']} 数据集统计信息:")
        logger.info(f"- 事件类型: {event_info['type']}")
        logger.info(f"- 攻击者地址: {event_info['address']}")
        logger.info(f"- 区块范围: {event_info['blockstart']} - {event_info['blockend']}")
        logger.info(f"- 唯一交易数: {df_save['tx_hash'].nunique()}")
        logger.info(f"- 总路径数: {len(df_save)}")
        logger.info(f"- 平均路径长度: {df_save['path_length'].mean():.2f}")
        logger.info(f"- 最大路径深度: {df_save['max_depth'].max()}")
        logger.info(f"- 包含转账的路径: {df_save['contains_transfer'].sum()}")
        logger.info(f"- 包含交换的路径: {df_save['contains_swap'].sum()}")
        logger.info(f"- 包含创建的路径: {df_save['contains_create'].sum()}")
        logger.info(f"- 包含授权的路径: {df_save['contains_approve'].sum()}")
        
        return output_path
    
    except Exception as e:
        logger.error(f"保存事件 {event_info['name']} 数据集时出错: {str(e)}")
        return ""

def save_dataset_summary(all_events_summary: List[Dict], output_format: str = 'csv', output_dir: str = 'path_datasets') -> str:
    """保存所有事件的汇总信息"""
    Path(output_dir).mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"events_summary_{timestamp}"
    
    if not all_events_summary:
        logger.warning("没有事件汇总数据可保存")
        return ""
    
    # 转换为DataFrame
    df = pd.DataFrame(all_events_summary)
    
    try:
        if output_format.lower() == 'csv':
            output_path = os.path.join(output_dir, f"{filename}.csv")
            df.to_csv(output_path, index=False, encoding='utf-8')
        elif output_format.lower() == 'excel':
            output_path = os.path.join(output_dir, f"{filename}.xlsx")
            df.to_excel(output_path, index=False, engine='openpyxl')
        elif output_format.lower() == 'parquet':
            output_path = os.path.join(output_dir, f"{filename}.parquet")
            df.to_parquet(output_path, index=False)
        else:
            raise ValueError(f"不支持的输出格式: {output_format}")
        
        logger.info(f"📁 事件汇总数据已保存到: {output_path}")
        logger.info(f"📊 汇总包含 {len(df)} 个事件")
        
        return output_path
    
    except Exception as e:
        logger.error(f"保存事件汇总数据时出错: {str(e)}")
        return ""

def main():
    """主函数"""
    logger.info("🚀 基于Web3区块扫描的路径级数据集构建脚本启动")
    
    # 配置参数
    excel_file = "SecurityEvent_dataset_v1.xlsx"
    max_events = 20  # 测试用，处理16个事件
    max_transactions_per_event = 1000  # 每个事件最多处理1000笔交易
    output_format = "excel"  # 改为excel格式，便于查看
    output_dir = "path_datasets"
    
    # 检查Excel文件
    if not os.path.exists(excel_file):
        logger.error(f"Excel文件不存在: {excel_file}")
        return
    
    # 检查环境变量
    ankr_key = "0e6456645648a5ce03caff65736c8b2bb1856fafa4ab1e3d6eadcce0ce0217a5"
    if not ankr_key:
        logger.error("❌ 需要配置ANKR_API_KEY环境变量")
        logger.error("请在.env文件中设置: ANKR_API_KEY=your_api_key")
        return
    
    # 初始化Web3区块链扫描器
    scanner = Web3BlockchainScanner()
    if not scanner.w3:
        logger.error("❌ Web3连接失败，无法继续")
        return
        
    logger.info("🔧 Web3区块链扫描器初始化完成")
    
    # 读取安全事件
    logger.info(f"📖 读取Excel文件: {excel_file}")
    events = read_security_events(excel_file, max_events)
    
    if not events:
        logger.error("没有读取到有效的安全事件数据")
        return
    
    logger.info(f"📋 准备处理 {len(events)} 个安全事件")
    
    # 为每个事件单独处理和保存
    saved_files = []
    events_summary = []
    total_paths = 0
    
    for i, event in enumerate(events, 1):
        try:
            logger.info(f"🎯 处理第 {i}/{len(events)} 个事件: {event['name']}")
            logger.info(f"📊 事件详情: {event['type']} | 地址: {event['address']} | 区块: {event['blockstart']}-{event['blockend']}")
            
            # 处理单个事件
            path_features = process_single_event(event, scanner, max_transactions_per_event)
            
            if path_features:
                # 为该事件保存单独的数据集文件
                output_path = save_event_dataset(path_features, event, output_format, output_dir)
                
                if output_path:
                    saved_files.append(output_path)
                    total_paths += len(path_features)
                    
                    # 记录事件汇总信息
                    event_summary = {
                        'event_id': event['event_id'],
                        'event_name': event['name'],
                        'event_type': event['type'],
                        'attacker_address': event['address'],
                        'block_start': event['blockstart'],
                        'block_end': event['blockend'],
                        'date': event.get('date', 'Unknown'),
                        'total_paths': len(path_features),
                        'unique_transactions': len(set(p['tx_hash'] for p in path_features)),
                        'avg_path_length': sum(p['path_length'] for p in path_features) / len(path_features),
                        'max_depth': max(p['max_depth'] for p in path_features),
                        'contains_transfer_count': sum(p['contains_transfer'] for p in path_features),
                        'contains_swap_count': sum(p['contains_swap'] for p in path_features),
                        'contains_create_count': sum(p['contains_create'] for p in path_features),
                        'contains_approve_count': sum(p['contains_approve'] for p in path_features),
                        'output_file': os.path.basename(output_path)
                    }
                    events_summary.append(event_summary)
                    
                    logger.info(f"✅ 事件 {event['name']} 处理完成并保存")
                else:
                    logger.warning(f"⚠️ 事件 {event['name']} 数据集保存失败")
            else:
                logger.warning(f"⚠️ 事件 {event['name']} 没有提取到路径数据")
                
        except Exception as e:
            logger.error(f"❌ 处理事件 {event['name']} 时出错: {str(e)}")
            traceback.print_exc()
            continue
    
    # 保存事件汇总信息
    if events_summary:
        summary_path = save_dataset_summary(events_summary, output_format, output_dir)
        if summary_path:
            saved_files.append(summary_path)
    
    # 输出最终统计
    logger.info("🎉 路径级数据集构建完成！")
    logger.info(f"📊 总体统计:")
    logger.info(f"- 处理事件数: {len(events_summary)}/{len(events)}")
    logger.info(f"- 总路径数: {total_paths}")
    logger.info(f"- 生成文件数: {len(saved_files)}")
    logger.info(f"📁 保存的文件:")
    for file_path in saved_files:
        logger.info(f"  - {file_path}")
    logger.info("🔗 基于Web3区块扫描 + Ankr trace获取 + analyze_user_behavior.py调用树重建")

if __name__ == "__main__":
    main()