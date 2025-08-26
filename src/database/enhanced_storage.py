#!/usr/bin/env python3
"""
增强数据存储层 - Enhanced Storage Layer
==============================================

提供高性能的合约、函数、事件等信息的存储和查询接口，
基于enhanced_schema.sql中的索引表，同时保持向后兼容性。

功能特性：
- 双写机制：新表优先，老表兼容
- 高性能索引查询
- 事务安全
- 错误恢复
- 性能监控
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import and_, or_, desc, asc, text
import time
import traceback

# 导入模型
from .models import Contract, UserInteraction
from .enhanced_models import (
    ContractSourceIndex, FunctionSignatureIndex, EventSignatureIndex,
    ContractCreatorIndex, AddressLabelIndex, TokenInfoIndex,
    MultiLayerGraphCache, IndexedDataAccess
)
from .crud import upsert_contract as legacy_upsert_contract


# 配置日志
logger = logging.getLogger(__name__)


class EnhancedStorageManager:
    """
    增强存储管理器
    
    提供统一的数据存储和查询接口，自动处理新旧表的兼容性
    """
    
    def __init__(self, db_session: Session, enable_legacy_compatibility: bool = True):
        """
        初始化存储管理器
        
        Args:
            db_session: 数据库会话
            enable_legacy_compatibility: 是否启用老表兼容模式
        """
        self.db_session = db_session
        self.enable_legacy_compatibility = enable_legacy_compatibility  # 保留原属性名
        self.legacy_mode = enable_legacy_compatibility  # 内部使用的属性名
        self.data_access = IndexedDataAccess(db_session)
        
        # 性能统计
        self.stats = {
            'operations': 0,
            'successes': 0,
            'failures': 0,
            'avg_response_time': 0,
            'total_response_time': 0,
            'contract_writes': 0,
            'function_writes': 0,
            'event_writes': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0
        }
        
        logger.info("增强存储管理器初始化完成")
    
    # ========================================
    # 合约信息存储与查询
    # ========================================
    
    def store_contract_info(self, contract_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        存储合约信息（新表优先，老表兼容）
        
        Args:
            contract_data: 合约数据字典，包含：
                - address: 合约地址
                - abi: ABI数据
                - source_code: 源码
                - contract_name: 合约名称
                - compiler_version: 编译器版本
                - network: 网络名称
                - verification_status: 验证状态
                - is_proxy: 是否为代理合约
                - parent_address: 父合约地址
        
        Returns:
            Tuple[bool, str]: (成功标志, 错误信息)
        """
        try:
            address = contract_data.get('address', '').lower()
            if not address:
                return False, "合约地址不能为空"
            
            # 1. 存储到新的索引表
            success, error_msg = self._store_to_contract_source_index(contract_data)
            if not success:
                logger.warning(f"存储到新索引表失败: {error_msg}")
                # 即使新表失败，也继续存储到老表以保证兼容性
            
            # 2. 兼容性：存储到老表
            if self.legacy_mode:
                try:
                    legacy_data = self._convert_to_legacy_format(contract_data)
                    legacy_upsert_contract(self.db_session, legacy_data)
                    logger.debug(f"合约 {address} 已同步到legacy表")
                except Exception as e:
                    logger.warning(f"同步到legacy表失败: {str(e)}")
            
            # 3. 更新统计
            self.stats['contract_writes'] += 1
            self.db_session.commit()
            
            logger.info(f"合约信息存储成功: {address}")
            return True, ""
            
        except Exception as e:
            self.db_session.rollback()
            self.stats['errors'] += 1
            error_msg = f"存储合约信息失败: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            return False, error_msg
    
    def get_contract_info(self, address: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        获取合约信息（优先从新索引表查询）
        
        Args:
            address: 合约地址
            use_cache: 是否使用缓存
            
        Returns:
            合约信息字典或None
        """
        try:
            address = address.lower()
            
            # 1. 优先从新索引表查询
            contract_info = self.data_access.get_contract_source_by_address(address)
            
            if contract_info:
                # 查询成功，转换为标准格式
                result = {
                    'address': contract_info.contract_address,
                    'contract_name': contract_info.contract_name,
                    'compiler_version': contract_info.compiler_version,
                    'network': contract_info.network,
                    'verification_status': contract_info.verification_status,
                    'created_at': contract_info.created_at,
                    'updated_at': contract_info.updated_at
                }
                
                # 如果有实际的源码和ABI，从原表或文件系统获取
                # 这里可以添加源码和ABI的实际获取逻辑
                
                logger.debug(f"从新索引表获取合约信息: {address}")
                return result
            
            # 2. 降级到legacy表查询
            if self.legacy_mode:
                from .crud import get_contract_full_info
                legacy_info = get_contract_full_info(self.db_session, address)
                if legacy_info:
                    logger.debug(f"从legacy表获取合约信息: {address}")
                    return legacy_info
            
            logger.debug(f"未找到合约信息: {address}")
            return None
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"查询合约信息失败: {str(e)}")
            return None
    
    def _store_to_contract_source_index(self, contract_data: Dict[str, Any]) -> Tuple[bool, str]:
        """存储到合约源码索引表"""
        try:
            address = contract_data.get('address', '').lower()
            
            # 计算源码和ABI的哈希
            source_code = contract_data.get('source_code', '')
            abi = contract_data.get('abi', [])
            
            source_code_hash = self._calculate_hash(source_code) if source_code else None
            abi_hash = self._calculate_hash(abi) if abi else None
            
            # 检查是否已存在
            existing = self.data_access.get_contract_source_by_address(address)
            
            if existing:
                # 更新现有记录
                existing.contract_name = contract_data.get('contract_name') or existing.contract_name
                existing.compiler_version = contract_data.get('compiler_version') or existing.compiler_version
                existing.verification_status = contract_data.get('verification_status', 'unverified')
                existing.source_code_hash = source_code_hash or existing.source_code_hash
                existing.abi_hash = abi_hash or existing.abi_hash
                existing.updated_at = datetime.utcnow()
            else:
                # 创建新记录
                new_contract = ContractSourceIndex(
                    contract_address=address,
                    source_code_hash=source_code_hash,
                    abi_hash=abi_hash,
                    contract_name=contract_data.get('contract_name', ''),
                    compiler_version=contract_data.get('compiler_version', ''),
                    network=contract_data.get('network', 'ethereum'),
                    verification_status=contract_data.get('verification_status', 'unverified')
                )
                self.db_session.add(new_contract)
            
            return True, ""
            
        except Exception as e:
            return False, str(e)
    
    # ========================================
    # 函数签名存储与查询
    # ========================================
    
    def store_function_signature(self, function_data: Dict[str, Any]) -> bool:
        """
        存储函数签名信息
        
        Args:
            function_data: 函数数据，包含：
                - selector: 函数选择器 (0x12345678)
                - signature: 完整函数签名
                - name: 函数名称
                - parameter_types: 参数类型列表
                - source_contract: 源合约地址
                - block_number: 发现的区块号
        
        Returns:
            bool: 存储是否成功
        """
        try:
            selector = function_data.get('selector', '').lower()
            if not selector.startswith('0x') or len(selector) != 10:
                logger.warning(f"无效的函数选择器: {selector}")
                return False
            
            # 查找现有记录
            existing = self.data_access.get_function_by_selector(selector)
            
            if existing:
                # 更新使用次数和最后发现区块
                existing.usage_count += 1
                existing.last_seen_block = function_data.get('block_number', existing.last_seen_block)
            else:
                # 创建新记录
                new_function = FunctionSignatureIndex(
                    function_selector=selector,
                    function_signature=function_data.get('signature', ''),
                    function_name=function_data.get('name', ''),
                    parameter_types=function_data.get('parameter_types', []),
                    source_contract=function_data.get('source_contract', '').lower(),
                    usage_count=1,
                    first_seen_block=function_data.get('block_number'),
                    last_seen_block=function_data.get('block_number')
                )
                self.db_session.add(new_function)
            
            self.stats['function_writes'] += 1
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"存储函数签名失败: {str(e)}")
            return False
    
    def get_function_by_selector(self, selector: str) -> Optional[Dict[str, Any]]:
        """
        通过选择器获取函数信息
        
        Args:
            selector: 函数选择器
            
        Returns:
            函数信息字典或None
        """
        try:
            function_info = self.data_access.get_function_by_selector(selector.lower())
            
            if function_info:
                return {
                    'selector': function_info.function_selector,
                    'signature': function_info.function_signature,
                    'name': function_info.function_name,
                    'parameter_types': function_info.parameter_types,
                    'source_contract': function_info.source_contract,
                    'usage_count': function_info.usage_count,
                    'first_seen_block': function_info.first_seen_block,
                    'last_seen_block': function_info.last_seen_block
                }
            
            return None
            
        except Exception as e:
            logger.error(f"查询函数签名失败: {str(e)}")
            return None
    
    # ========================================
    # 事件签名存储与查询
    # ========================================
    
    def store_event_signature(self, event_data: Dict[str, Any]) -> bool:
        """
        存储事件签名信息
        
        Args:
            event_data: 事件数据，包含：
                - topic0: 事件topic0哈希
                - signature: 完整事件签名
                - name: 事件名称
                - indexed_params: 索引参数类型
                - non_indexed_params: 非索引参数类型
                - source_contract: 源合约地址
                - block_number: 发现的区块号
        
        Returns:
            bool: 存储是否成功
        """
        try:
            topic0 = event_data.get('topic0', '').lower()
            if not topic0.startswith('0x') or len(topic0) != 66:
                logger.warning(f"无效的事件topic0: {topic0}")
                return False
            
            # 查找现有记录
            existing = self.data_access.get_event_by_topic0(topic0)
            
            if existing:
                # 更新使用次数
                existing.usage_count += 1
                existing.last_seen_block = event_data.get('block_number', existing.last_seen_block)
            else:
                # 创建新记录
                new_event = EventSignatureIndex(
                    event_topic0=topic0,
                    event_signature=event_data.get('signature', ''),
                    event_name=event_data.get('name', ''),
                    indexed_params=event_data.get('indexed_params', []),
                    non_indexed_params=event_data.get('non_indexed_params', []),
                    source_contract=event_data.get('source_contract', '').lower(),
                    usage_count=1,
                    first_seen_block=event_data.get('block_number'),
                    last_seen_block=event_data.get('block_number')
                )
                self.db_session.add(new_event)
            
            self.stats['event_writes'] += 1
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"存储事件签名失败: {str(e)}")
            return False
    
    def get_event_by_topic0(self, topic0: str) -> Optional[Dict[str, Any]]:
        """
        通过topic0获取事件信息
        
        Args:
            topic0: 事件topic0哈希
            
        Returns:
            事件信息字典或None
        """
        try:
            event_info = self.data_access.get_event_by_topic0(topic0.lower())
            
            if event_info:
                return {
                    'topic0': event_info.event_topic0,
                    'signature': event_info.event_signature,
                    'name': event_info.event_name,
                    'indexed_params': event_info.indexed_params,
                    'non_indexed_params': event_info.non_indexed_params,
                    'source_contract': event_info.source_contract,
                    'usage_count': event_info.usage_count,
                    'first_seen_block': event_info.first_seen_block,
                    'last_seen_block': event_info.last_seen_block
                }
            
            return None
            
        except Exception as e:
            logger.error(f"查询事件签名失败: {str(e)}")
            return None
    
    # ========================================
    # 合约创建者信息存储与查询
    # ========================================
    
    def store_contract_creator(self, creator_data: Dict[str, Any]) -> bool:
        """
        存储合约创建者信息
        
        Args:
            creator_data: 创建者数据，包含：
                - contract_address: 合约地址
                - creator_address: 创建者地址
                - creation_tx_hash: 创建交易哈希
                - creation_block_number: 创建区块号
                - creation_timestamp: 创建时间
                - constructor_params: 构造函数参数
                - creation_value: 创建时发送的ETH
                - factory_contract: 工厂合约地址
        
        Returns:
            bool: 存储是否成功
        """
        try:
            contract_address = creator_data.get('contract_address', '').lower()
            creator_address = creator_data.get('creator_address', '').lower()
            
            if not contract_address or not creator_address:
                return False
            
            # 检查是否已存在
            existing = self.data_access.get_contract_creator(contract_address)
            
            if not existing:
                new_creator = ContractCreatorIndex(
                    contract_address=contract_address,
                    creator_address=creator_address,
                    creation_tx_hash=creator_data.get('creation_tx_hash', ''),
                    creation_block_number=creator_data.get('creation_block_number', 0),
                    creation_timestamp=creator_data.get('creation_timestamp'),
                    constructor_params=creator_data.get('constructor_params', ''),
                    creation_value=creator_data.get('creation_value', '0'),
                    factory_contract=creator_data.get('factory_contract', '').lower() if creator_data.get('factory_contract') else None,
                    creation_method=creator_data.get('creation_method', ''),
                    network=creator_data.get('network', 'ethereum')
                )
                self.db_session.add(new_creator)
                return True
            
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"存储合约创建者信息失败: {str(e)}")
            return False
    
    def get_contract_creator(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        获取合约创建者信息
        
        Args:
            contract_address: 合约地址
            
        Returns:
            创建者信息字典或None
        """
        try:
            creator_info = self.data_access.get_contract_creator(contract_address.lower())
            
            if creator_info:
                return {
                    'contract_address': creator_info.contract_address,
                    'creator_address': creator_info.creator_address,
                    'creation_tx_hash': creator_info.creation_tx_hash,
                    'creation_block_number': creator_info.creation_block_number,
                    'creation_timestamp': creator_info.creation_timestamp,
                    'constructor_params': creator_info.constructor_params,
                    'creation_value': creator_info.creation_value,
                    'factory_contract': creator_info.factory_contract,
                    'creation_method': creator_info.creation_method,
                    'network': creator_info.network
                }
            
            return None
            
        except Exception as e:
            logger.error(f"查询合约创建者信息失败: {str(e)}")
            return None
    
    # ========================================
    # 交互数据存储（兼容原有接口）
    # ========================================
    
    def store_interaction(self, interaction_data: Dict[str, Any]) -> bool:
        """
        存储交互数据（兼容原有save_interaction接口）
        
        Args:
            interaction_data: 交互数据，包含：
                - target_contract: 目标合约
                - caller_contract: 调用者合约
                - method_name: 方法名称
                - block_number: 区块号
                - tx_hash: 交易哈希
                - timestamp: 时间戳
                - input_data: 输入数据
                - network: 网络
                - transfer_amount: 转账金额
                - token_address: 代币地址
                - is_token_transfer: 是否为代币转账
        
        Returns:
            bool: 存储是否成功
        """
        try:
            # 检查必要字段
            required_fields = ['target_contract', 'caller_contract', 'method_name', 
                             'block_number', 'tx_hash', 'timestamp']
            
            for field in required_fields:
                if not interaction_data.get(field):
                    logger.warning(f"缺少必要字段: {field}")
                    return False
            
            # 检查是否已存在相同的交易哈希
            existing = self.db_session.query(UserInteraction).filter(
                UserInteraction.tx_hash == interaction_data['tx_hash']
            ).first()
            
            if existing:
                # 更新现有记录
                for key, value in interaction_data.items():
                    if hasattr(existing, key) and value is not None:
                        setattr(existing, key, value)
            else:
                # 创建新记录
                new_interaction = UserInteraction(
                    target_contract=interaction_data['target_contract'].lower(),
                    caller_contract=interaction_data['caller_contract'].lower(),
                    method_name=interaction_data['method_name'],
                    block_number=interaction_data['block_number'],
                    tx_hash=interaction_data['tx_hash'],
                    timestamp=interaction_data['timestamp'],
                    input_data=interaction_data.get('input_data', ''),
                    event_logs=interaction_data.get('event_logs'),
                    trace_data=interaction_data.get('trace_data'),
                    network=interaction_data.get('network', 'ethereum'),
                    transfer_amount=interaction_data.get('transfer_amount', '0'),
                    token_address=interaction_data.get('token_address'),
                    is_token_transfer=interaction_data.get('is_token_transfer', False)
                )
                self.db_session.add(new_interaction)
            
            # 同时尝试提取和存储函数签名信息
            if interaction_data.get('input_data'):
                self._extract_and_store_function_signature(interaction_data)
            
            return True
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"存储交互数据失败: {str(e)}")
            return False
    
    def _extract_and_store_function_signature(self, interaction_data: Dict[str, Any]):
        """从交互数据中提取并存储函数签名"""
        try:
            input_data = interaction_data.get('input_data', '')
            if not input_data or len(input_data) < 10:
                return
            
            # 提取函数选择器
            if input_data.startswith('0x'):
                selector = input_data[:10]
            else:
                selector = '0x' + input_data[:8]
            
            # 存储函数签名
            function_data = {
                'selector': selector,
                'signature': interaction_data.get('method_name', '') + '()',
                'name': interaction_data.get('method_name', ''),
                'parameter_types': [],  # 这里可以进一步解析参数类型
                'source_contract': interaction_data.get('target_contract', ''),
                'block_number': interaction_data.get('block_number')
            }
            
            self.store_function_signature(function_data)
            
        except Exception as e:
            logger.debug(f"提取函数签名失败: {str(e)}")
    
    # ========================================
    # 工具方法
    # ========================================
    
    def _calculate_hash(self, data: Union[str, List, Dict]) -> str:
        """计算数据的SHA256哈希值"""
        if isinstance(data, (list, dict)):
            data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    
    def _convert_to_legacy_format(self, contract_data: Dict[str, Any]) -> Dict[str, Any]:
        """将新格式的合约数据转换为legacy格式"""
        return {
            'target_contract': contract_data.get('address', ''),
            'abi': contract_data.get('abi', []),
            'source_code': contract_data.get('source_code', ''),
            'contract_name': contract_data.get('contract_name', ''),
            'c_name': contract_data.get('contract_name', ''),
            'network': contract_data.get('network', 'ethereum'),
            'is_proxy': contract_data.get('is_proxy', False),
            'parent_address': contract_data.get('parent_address'),
            'created_at': datetime.utcnow()
        }
    
    def commit_transaction(self) -> bool:
        """提交事务"""
        try:
            self.db_session.commit()
            return True
        except Exception as e:
            self.db_session.rollback()
            logger.error(f"提交事务失败: {str(e)}")
            return False
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计信息"""
        total_ops = self.stats['operations']
        success_rate = (self.stats['successes'] / max(total_ops, 1)) * 100
        
        return {
            'operations': self.stats['operations'],
            'successes': self.stats['successes'],
            'failures': self.stats['failures'],
            'success_rate': success_rate,
            'avg_response_time': self.stats['avg_response_time'],
            'total_response_time': self.stats['total_response_time'],
            'contract_writes': self.stats['contract_writes'],
            'function_writes': self.stats['function_writes'],
            'event_writes': self.stats['event_writes'],
            'cache_hits': self.stats['cache_hits'],
            'cache_misses': self.stats['cache_misses'],
            'errors': self.stats['errors'],
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def reset_stats(self):
        """重置性能统计"""
        self.stats = {
            'operations': 0,
            'successes': 0,
            'failures': 0,
            'avg_response_time': 0,
            'total_response_time': 0,
            'contract_writes': 0,
            'function_writes': 0,
            'event_writes': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0
        }

    # ===== 增强数据查询层 =====
    # 所有查询优先使用索引表，提供高性能查询接口
    
    def query_contracts_by_address_batch(self, addresses: List[str], 
                                       include_source: bool = False,
                                       include_abi: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        批量查询多个合约的基本信息（优化版本）
        
        Args:
            addresses: 合约地址列表
            include_source: 是否包含源码
            include_abi: 是否包含ABI
            
        Returns:
            Dict[address, contract_info]: 合约地址到信息的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化地址格式
            normalized_addresses = [addr.lower() for addr in addresses]
            
            # 使用索引表进行批量查询
            contracts = self.db_session.query(ContractSourceIndex).filter(
                ContractSourceIndex.contract_address.in_(normalized_addresses)
            ).all()
            
            # 如果需要详细信息，补充查询老表
            if include_source or include_abi:
                # 查询老表获取详细信息
                legacy_contracts = self.db_session.query(Contract).filter(
                    Contract.target_contract.in_(normalized_addresses)
                ).all()
                
                # 创建老表数据的映射
                legacy_map = {c.target_contract: c for c in legacy_contracts}
            else:
                legacy_map = {}
            
            # 组装结果
            for contract in contracts:
                addr = contract.contract_address
                contract_info = {
                    'address': addr,
                    'contract_name': contract.contract_name,
                    'compiler_version': contract.compiler_version,
                    'network': contract.network,
                    'verification_status': contract.verification_status,
                    'created_at': contract.created_at,
                    'source_code_hash': contract.source_code_hash,
                    'abi_hash': contract.abi_hash
                }
                
                # 添加详细信息（如果需要）
                if include_source or include_abi:
                    legacy_contract = legacy_map.get(addr)
                    if legacy_contract:
                        if include_source:
                            contract_info['source_code'] = legacy_contract.source_code
                        if include_abi:
                            contract_info['abi'] = legacy_contract.abi
                
                result[addr] = contract_info
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"批量查询 {len(addresses)} 个合约，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"批量查询合约失败: {str(e)}")
            return result

    def query_functions_by_selectors(self, selectors: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        批量查询函数签名（使用高性能索引）
        
        Args:
            selectors: 函数选择器列表，格式如 ['0x12345678', '0xabcdef00']
            
        Returns:
            Dict[selector, function_info]: 选择器到函数信息的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化选择器格式
            normalized_selectors = []
            for sel in selectors:
                if isinstance(sel, str):
                    if not sel.startswith('0x'):
                        sel = '0x' + sel
                    if len(sel) == 10:  # 0x + 8位十六进制
                        normalized_selectors.append(sel.lower())
            
            if not normalized_selectors:
                return result
            
            # 使用索引表查询
            functions = self.db_session.query(FunctionSignatureIndex).filter(
                FunctionSignatureIndex.function_selector.in_(normalized_selectors)
            ).all()
            
            # 组装结果
            for func in functions:
                result[func.function_selector] = {
                    'selector': func.function_selector,
                    'signature': func.function_signature,
                    'name': func.function_name,
                    'parameter_types': func.parameter_types,
                    'source_contract': func.source_contract,
                    'usage_count': func.usage_count,
                    'first_seen_block': func.first_seen_block,
                    'last_seen_block': func.last_seen_block
                }
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"批量查询 {len(normalized_selectors)} 个函数选择器，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"批量查询函数签名失败: {str(e)}")
            return result

    def query_events_by_topics(self, topics: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        批量查询事件签名（使用高性能索引）
        
        Args:
            topics: 事件topic0列表，格式如 ['0x1234...', '0xabcd...']
            
        Returns:
            Dict[topic0, event_info]: topic0到事件信息的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化topic格式
            normalized_topics = []
            for topic in topics:
                if isinstance(topic, str):
                    if not topic.startswith('0x'):
                        topic = '0x' + topic
                    if len(topic) == 66:  # 0x + 64位十六进制
                        normalized_topics.append(topic.lower())
            
            if not normalized_topics:
                return result
            
            # 使用索引表查询
            events = self.db_session.query(EventSignatureIndex).filter(
                EventSignatureIndex.event_topic0.in_(normalized_topics)
            ).all()
            
            # 组装结果
            for event in events:
                result[event.event_topic0] = {
                    'topic0': event.event_topic0,
                    'signature': event.event_signature,
                    'name': event.event_name,
                    'indexed_params': event.indexed_params,
                    'non_indexed_params': event.non_indexed_params,
                    'source_contract': event.source_contract,
                    'usage_count': event.usage_count,
                    'first_seen_block': event.first_seen_block,
                    'last_seen_block': event.last_seen_block
                }
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"批量查询 {len(normalized_topics)} 个事件topic，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"批量查询事件签名失败: {str(e)}")
            return result

    def query_contracts_by_creator(self, creator_address: str, 
                                 limit: int = 100,
                                 include_factory_contracts: bool = True) -> List[Dict[str, Any]]:
        """
        查询特定创建者创建的所有合约（使用创建者索引）
        
        Args:
            creator_address: 创建者地址
            limit: 返回数量限制
            include_factory_contracts: 是否包含通过工厂合约创建的
            
        Returns:
            List[contract_info]: 合约信息列表
        """
        start_time = time.time()
        result = []
        
        try:
            creator_address = creator_address.lower()
            
            # 构建查询条件
            query = self.db_session.query(ContractCreatorIndex).filter(
                ContractCreatorIndex.creator_address == creator_address
            )
            
            if not include_factory_contracts:
                query = query.filter(ContractCreatorIndex.factory_contract.is_(None))
            
            # 执行查询，按创建时间降序排序
            contracts = query.order_by(
                ContractCreatorIndex.creation_block_number.desc()
            ).limit(limit).all()
            
            # 组装结果
            for contract in contracts:
                result.append({
                    'contract_address': contract.contract_address,
                    'creator_address': contract.creator_address,
                    'creation_tx_hash': contract.creation_tx_hash,
                    'creation_block_number': contract.creation_block_number,
                    'creation_timestamp': contract.creation_timestamp,
                    'constructor_params': contract.constructor_params,
                    'creation_value': contract.creation_value,
                    'factory_contract': contract.factory_contract,
                    'creation_method': contract.creation_method,
                    'network': contract.network
                })
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"查询创建者 {creator_address} 的合约，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"查询创建者合约失败: {str(e)}")
            return result

    def query_address_labels(self, addresses: List[str], 
                           label_types: List[str] = None,
                           verified_only: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        查询地址标签信息（使用标签索引）
        
        Args:
            addresses: 地址列表
            label_types: 标签类型过滤器（可选）
            verified_only: 是否只返回已验证的标签
            
        Returns:
            Dict[address, List[label_info]]: 地址到标签列表的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化地址格式
            normalized_addresses = [addr.lower() for addr in addresses]
            
            # 构建查询条件
            query = self.db_session.query(AddressLabelIndex).filter(
                AddressLabelIndex.address.in_(normalized_addresses)
            )
            
            if label_types:
                query = query.filter(AddressLabelIndex.label_type.in_(label_types))
            
            if verified_only:
                query = query.filter(AddressLabelIndex.verified == True)
            
            # 执行查询，按置信度降序排序
            labels = query.order_by(
                AddressLabelIndex.confidence_score.desc()
            ).all()
            
            # 组装结果
            for label in labels:
                addr = label.address
                if addr not in result:
                    result[addr] = []
                
                result[addr].append({
                    'label_type': label.label_type,
                    'label_name': label.label_name,
                    'label_source': label.label_source,
                    'confidence_score': float(label.confidence_score),
                    'additional_info': label.additional_info,
                    'verified': label.verified,
                    'network': label.network,
                    'created_at': label.created_at
                })
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"查询 {len(normalized_addresses)} 个地址标签，找到 {len(labels)} 个标签，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"查询地址标签失败: {str(e)}")
            return result

    def query_token_info_batch(self, token_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        批量查询代币信息（使用代币索引）
        
        Args:
            token_addresses: 代币合约地址列表
            
        Returns:
            Dict[address, token_info]: 代币地址到信息的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化地址格式
            normalized_addresses = [addr.lower() for addr in token_addresses]
            
            # 使用索引表查询
            tokens = self.db_session.query(TokenInfoIndex).filter(
                TokenInfoIndex.token_address.in_(normalized_addresses)
            ).all()
            
            # 组装结果
            for token in tokens:
                result[token.token_address] = {
                    'token_address': token.token_address,
                    'symbol': token.token_symbol,
                    'name': token.token_name,
                    'decimals': token.token_decimals,
                    'total_supply': token.token_total_supply,
                    'token_type': token.token_type,
                    'creator_address': token.creator_address,
                    'creation_block': token.creation_block,
                    'is_mintable': token.is_mintable,
                    'is_burnable': token.is_burnable,
                    'is_pausable': token.is_pausable,
                    'proxy_implementation': token.proxy_implementation,
                    'network': token.network,
                    'verification_status': token.verification_status
                }
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"批量查询 {len(normalized_addresses)} 个代币，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"批量查询代币信息失败: {str(e)}")
            return result

    def query_interactions_by_contracts(self, contract_addresses: List[str],
                                      start_block: int = None,
                                      end_block: int = None,
                                      limit: int = 1000,
                                      method_names: List[str] = None) -> List[Dict[str, Any]]:
        """
        查询合约交互数据（使用优化索引）
        
        Args:
            contract_addresses: 合约地址列表
            start_block: 起始区块（可选）
            end_block: 结束区块（可选）
            limit: 返回数量限制
            method_names: 方法名过滤器（可选）
            
        Returns:
            List[interaction_info]: 交互信息列表
        """
        start_time = time.time()
        result = []
        
        try:
            # 规范化地址格式
            normalized_addresses = [addr.lower() for addr in contract_addresses]
            
            # 构建查询条件
            query = self.db_session.query(UserInteraction).filter(
                or_(
                    UserInteraction.target_contract.in_(normalized_addresses),
                    UserInteraction.caller_contract.in_(normalized_addresses)
                )
            )
            
            # 添加区块范围过滤
            if start_block is not None:
                query = query.filter(UserInteraction.block_number >= start_block)
            if end_block is not None:
                query = query.filter(UserInteraction.block_number <= end_block)
            
            # 添加方法名过滤
            if method_names:
                query = query.filter(UserInteraction.method_name.in_(method_names))
            
            # 执行查询，按区块号降序排序
            interactions = query.order_by(
                UserInteraction.block_number.desc()
            ).limit(limit).all()
            
            # 组装结果
            for interaction in interactions:
                result.append({
                    'target_contract': interaction.target_contract,
                    'caller_contract': interaction.caller_contract,
                    'method_name': interaction.method_name,
                    'block_number': interaction.block_number,
                    'tx_hash': interaction.tx_hash,
                    'timestamp': interaction.timestamp,
                    'input_data': interaction.input_data,
                    'transfer_amount': interaction.transfer_amount,
                    'token_address': interaction.token_address,
                    'is_token_transfer': interaction.is_token_transfer,
                    'network': interaction.network
                })
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"查询 {len(normalized_addresses)} 个合约的交互，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"查询合约交互失败: {str(e)}")
            return result

    def query_high_usage_functions(self, min_usage_count: int = 10,
                                 network: str = 'ethereum',
                                 limit: int = 100) -> List[Dict[str, Any]]:
        """
        查询高使用频率的函数（用于安全分析）
        
        Args:
            min_usage_count: 最小使用次数
            network: 网络名称
            limit: 返回数量限制
            
        Returns:
            List[function_info]: 高频函数列表
        """
        start_time = time.time()
        result = []
        
        try:
            # 查询高使用频率的函数
            functions = self.db_session.query(FunctionSignatureIndex).filter(
                FunctionSignatureIndex.usage_count >= min_usage_count
            ).order_by(
                FunctionSignatureIndex.usage_count.desc()
            ).limit(limit).all()
            
            # 组装结果
            for func in functions:
                result.append({
                    'selector': func.function_selector,
                    'signature': func.function_signature,
                    'name': func.function_name,
                    'usage_count': func.usage_count,
                    'source_contract': func.source_contract,
                    'first_seen_block': func.first_seen_block,
                    'last_seen_block': func.last_seen_block,
                    'parameter_types': func.parameter_types
                })
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"查询高频函数（>={min_usage_count}次），找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"查询高频函数失败: {str(e)}")
            return result

    def query_contract_verification_status(self, addresses: List[str]) -> Dict[str, str]:
        """
        快速查询合约验证状态
        
        Args:
            addresses: 合约地址列表
            
        Returns:
            Dict[address, status]: 地址到验证状态的映射
        """
        start_time = time.time()
        result = {}
        
        try:
            # 规范化地址格式
            normalized_addresses = [addr.lower() for addr in addresses]
            
            # 使用索引表查询（只查询必要字段，提高性能）
            contracts = self.db_session.query(
                ContractSourceIndex.contract_address,
                ContractSourceIndex.verification_status
            ).filter(
                ContractSourceIndex.contract_address.in_(normalized_addresses)
            ).all()
            
            # 组装结果
            for contract_address, verification_status in contracts:
                result[contract_address] = verification_status
            
            # 对于未找到的地址，标记为未知
            for addr in normalized_addresses:
                if addr not in result:
                    result[addr] = 'unknown'
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"查询 {len(normalized_addresses)} 个合约验证状态，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"查询合约验证状态失败: {str(e)}")
            # 返回默认状态
            return {addr.lower(): 'unknown' for addr in addresses}

    def search_contracts_by_name(self, name_pattern: str, 
                               verified_only: bool = True,
                               limit: int = 50) -> List[Dict[str, Any]]:
        """
        按合约名称搜索合约（支持模糊匹配）
        
        Args:
            name_pattern: 名称匹配模式
            verified_only: 是否只搜索已验证的合约
            limit: 返回数量限制
            
        Returns:
            List[contract_info]: 匹配的合约列表
        """
        start_time = time.time()
        result = []
        
        try:
            # 构建查询条件
            query = self.db_session.query(ContractSourceIndex).filter(
                ContractSourceIndex.contract_name.ilike(f'%{name_pattern}%')
            )
            
            if verified_only:
                query = query.filter(ContractSourceIndex.verification_status == 'verified')
            
            # 执行查询
            contracts = query.order_by(
                ContractSourceIndex.created_at.desc()
            ).limit(limit).all()
            
            # 组装结果
            for contract in contracts:
                result.append({
                    'address': contract.contract_address,
                    'contract_name': contract.contract_name,
                    'compiler_version': contract.compiler_version,
                    'verification_status': contract.verification_status,
                    'network': contract.network,
                    'created_at': contract.created_at
                })
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"搜索合约名称 '{name_pattern}'，找到 {len(result)} 个，耗时 {response_time:.3f}s")
            return result
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"搜索合约名称失败: {str(e)}")
            return result

    def get_network_statistics(self, network: str = 'ethereum') -> Dict[str, Any]:
        """
        获取网络统计信息（使用索引表快速统计）
        
        Args:
            network: 网络名称
            
        Returns:
            Dict: 统计信息
        """
        start_time = time.time()
        
        try:
            stats = {}
            
            # 合约统计
            total_contracts = self.db_session.query(ContractSourceIndex).filter(
                ContractSourceIndex.network == network
            ).count()
            
            verified_contracts = self.db_session.query(ContractSourceIndex).filter(
                ContractSourceIndex.network == network,
                ContractSourceIndex.verification_status == 'verified'
            ).count()
            
            # 函数统计
            total_functions = self.db_session.query(FunctionSignatureIndex).count()
            
            # 事件统计
            total_events = self.db_session.query(EventSignatureIndex).count()
            
            # 代币统计
            total_tokens = self.db_session.query(TokenInfoIndex).filter(
                TokenInfoIndex.network == network
            ).count()
            
            stats = {
                'network': network,
                'total_contracts': total_contracts,
                'verified_contracts': verified_contracts,
                'verification_rate': round(verified_contracts / max(total_contracts, 1) * 100, 2),
                'total_functions': total_functions,
                'total_events': total_events,
                'total_tokens': total_tokens,
                'updated_at': datetime.now()
            }
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"获取 {network} 网络统计，耗时 {response_time:.3f}s")
            return stats
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"获取网络统计失败: {str(e)}")
            return {'network': network, 'error': str(e)}

    def _update_stats(self, success: bool, response_time: float):
        """更新性能统计（内部方法）"""
        self.stats['operations'] += 1
        self.stats['total_response_time'] += response_time
        self.stats['avg_response_time'] = self.stats['total_response_time'] / self.stats['operations']
        
        if success:
            self.stats['successes'] += 1
        else:
            self.stats['failures'] += 1

    # ===== 智能缓存查询接口 =====
    
    def get_cached_call_graph(self, target_contract: str, 
                            start_block: int, 
                            end_block: int,
                            analysis_type: str = 'security') -> Optional[Dict[str, Any]]:
        """
        获取缓存的调用图数据
        
        Args:
            target_contract: 目标合约地址
            start_block: 起始区块
            end_block: 结束区块
            analysis_type: 分析类型
            
        Returns:
            缓存的图数据或None
        """
        start_time = time.time()
        
        try:
            # 生成缓存键
            cache_key = self._generate_cache_key(target_contract, start_block, end_block, analysis_type)
            
            # 查询缓存
            cached_graph = self.db_session.query(MultiLayerGraphCache).filter(
                MultiLayerGraphCache.cache_key == cache_key,
                MultiLayerGraphCache.expires_at > datetime.now()
            ).first()
            
            if cached_graph:
                # 更新访问统计
                cached_graph.access_count += 1
                cached_graph.last_accessed = datetime.now()
                self.db_session.commit()
                
                # 记录性能统计
                response_time = time.time() - start_time
                self._update_stats(True, response_time)
                
                print(f"命中缓存的调用图，耗时 {response_time:.3f}s")
                return {
                    'graph_data': cached_graph.graph_data,
                    'related_addresses': cached_graph.related_addresses,
                    'node_count': cached_graph.node_count,
                    'layer_count': cached_graph.layer_count,
                    'cached': True,
                    'cache_created': cached_graph.created_at
                }
            
            return None
            
        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            print(f"获取缓存调用图失败: {str(e)}")
            return None

    def cache_call_graph(self, target_contract: str,
                        start_block: int,
                        end_block: int,
                        graph_data: Dict[str, Any],
                        related_addresses: List[str],
                        analysis_type: str = 'security',
                        cache_hours: int = 24) -> bool:
        """
        缓存调用图数据
        
        Args:
            target_contract: 目标合约地址
            start_block: 起始区块
            end_block: 结束区块
            graph_data: 图数据
            related_addresses: 相关地址列表
            analysis_type: 分析类型
            cache_hours: 缓存小时数
            
        Returns:
            是否成功缓存
        """
        start_time = time.time()
        
        try:
            # 生成缓存键
            cache_key = self._generate_cache_key(target_contract, start_block, end_block, analysis_type)
            
            # 计算过期时间
            expires_at = datetime.now() + timedelta(hours=cache_hours)
            
            # 统计图信息
            node_count = len(graph_data.get('nodes', []))
            layer_count = len(set(node.get('layer', 0) for node in graph_data.get('nodes', [])))
            
            # 创建缓存记录
            cache_record = MultiLayerGraphCache(
                cache_key=cache_key,
                target_contract=target_contract.lower(),
                start_block=start_block,
                end_block=end_block,
                graph_data=graph_data,
                related_addresses=related_addresses,
                analysis_type=analysis_type,
                node_count=node_count,
                layer_count=layer_count,
                network='ethereum',
                expires_at=expires_at
            )
            
            # 保存到数据库
            self.db_session.merge(cache_record)  # 使用merge避免重复键冲突
            self.db_session.commit()
            
            # 记录性能统计
            response_time = time.time() - start_time
            self._update_stats(True, response_time)
            
            print(f"缓存调用图成功，缓存键: {cache_key}，耗时 {response_time:.3f}s")
            return True
            
        except Exception as e:
            self.db_session.rollback()
            self._update_stats(False, time.time() - start_time)
            print(f"缓存调用图失败: {str(e)}")
            return False

    def _generate_cache_key(self, target_contract: str, start_block: int, 
                          end_block: int, analysis_type: str) -> str:
        """生成缓存键"""
        key_data = f"{target_contract.lower()}_{start_block}_{end_block}_{analysis_type}"
        return self._calculate_hash(key_data)[:32]  # 使用前32个字符作为键


# ========================================
# 便捷函数接口（保持与原有接口兼容）
# ========================================

def create_enhanced_storage(db_session: Session, enable_legacy: bool = True) -> EnhancedStorageManager:
    """
    创建增强存储管理器实例
    
    Args:
        db_session: 数据库会话
        enable_legacy: 是否启用legacy兼容模式
        
    Returns:
        EnhancedStorageManager: 存储管理器实例
    """
    return EnhancedStorageManager(db_session, enable_legacy)


def enhanced_upsert_contract(db_session: Session, contract_data: Dict[str, Any]) -> bool:
    """
    增强版合约信息插入/更新（向后兼容接口）
    
    Args:
        db_session: 数据库会话
        contract_data: 合约数据
        
    Returns:
        bool: 操作是否成功
    """
    storage = create_enhanced_storage(db_session)
    success, _ = storage.store_contract_info(contract_data)
    if success:
        storage.commit_transaction()
    return success


def enhanced_save_interaction(db_session: Session, interaction_data: Dict[str, Any]) -> bool:
    """
    增强版交互数据保存（向后兼容接口）
    
    Args:
        db_session: 数据库会话
        interaction_data: 交互数据
        
    Returns:
        bool: 操作是否成功
    """
    storage = create_enhanced_storage(db_session)
    success = storage.store_interaction(interaction_data)
    if success:
        storage.commit_transaction()
    return success


# ========================================
# 批量操作接口
# ========================================

def batch_store_interactions(db_session: Session, interactions: List[Dict[str, Any]], 
                           batch_size: int = 1000) -> Tuple[int, int]:
    """
    批量存储交互数据
    
    Args:
        db_session: 数据库会话
        interactions: 交互数据列表
        batch_size: 批次大小
        
    Returns:
        Tuple[int, int]: (成功数量, 失败数量)
    """
    storage = create_enhanced_storage(db_session)
    success_count = 0
    error_count = 0
    
    for i in range(0, len(interactions), batch_size):
        batch = interactions[i:i+batch_size]
        
        try:
            for interaction in batch:
                if storage.store_interaction(interaction):
                    success_count += 1
                else:
                    error_count += 1
            
            # 每个批次提交一次
            storage.commit_transaction()
            logger.info(f"批次 {i//batch_size + 1} 完成: {len(batch)} 条记录")
            
        except Exception as e:
            error_count += len(batch)
            logger.error(f"批次 {i//batch_size + 1} 失败: {str(e)}")
    
    logger.info(f"批量存储完成: 成功 {success_count}, 失败 {error_count}")
    return success_count, error_count


if __name__ == "__main__":
    # 测试代码
    print("增强存储层模块已加载") 