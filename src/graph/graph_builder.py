"""
图构建器 - 从现有数据构建多层图结构
"""
import json
import traceback
from typing import Dict, List, Set, Optional, Any, Tuple
from decimal import Decimal
from web3 import Web3

from .graph_layers import (
    MultiLayerGraph, GraphLayer, NodeType, AddressType,
    AddressNode, TransactionNode, FunctionCallNode, EventNode, TokenTransferNode,
    ensure_json_serializable
)
from database import get_db
from database.models import UserInteraction, Contract
from database.crud import get_contract_full_info


class GraphBuilder:
    """多层图构建器"""
    
    def __init__(self):
        self.db = next(get_db())
        self.address_cache = {}  # 缓存地址信息
        self.contract_cache = {}  # 缓存合约信息
    
    def build_multilayer_graph(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int,
        related_addresses: List[str] = None,
        call_graph: Dict = None,
        include_layers: List[NodeType] = None
    ) -> MultiLayerGraph:
        """构建完整的多层图"""
        
        # 默认包含所有层
        if include_layers is None:
            include_layers = [
                NodeType.ADDRESS, 
                NodeType.TRANSACTION, 
                NodeType.FUNCTION_CALL, 
                NodeType.EVENT
            ]
        
        print(f"开始构建多层图: 目标合约={target_contract}, 区块范围=[{start_block}, {end_block}]")
        
        # 创建多层图对象
        graph = MultiLayerGraph(
            graph_id=f"{target_contract}_{start_block}_{end_block}",
            target_contract=target_contract.lower(),
            time_range=[start_block, end_block]
        )
        
        # 收集所有相关地址
        all_addresses = self._collect_all_addresses(
            target_contract, start_block, end_block, related_addresses, call_graph
        )
        
        # 构建各层
        if NodeType.ADDRESS in include_layers:
            address_layer = self._build_address_layer(all_addresses, start_block, end_block)
            graph.add_layer(address_layer)
        
        if NodeType.TRANSACTION in include_layers:
            transaction_layer = self._build_transaction_layer(
                target_contract, start_block, end_block, all_addresses
            )
            graph.add_layer(transaction_layer)
        
        if NodeType.FUNCTION_CALL in include_layers and call_graph:
            function_layer = self._build_function_call_layer(call_graph, all_addresses)
            graph.add_layer(function_layer)
        
        if NodeType.EVENT in include_layers:
            event_layer = self._build_event_layer(
                target_contract, start_block, end_block, all_addresses
            )
            graph.add_layer(event_layer)
        
        print(f"多层图构建完成: {len(graph.layers)} 层, 总节点数: {graph.global_stats['total_nodes']}")
        return graph
    
    def _collect_all_addresses(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int,
        related_addresses: List[str] = None,
        call_graph: Dict = None
    ) -> Set[str]:
        """收集所有相关地址"""
        
        addresses = set()
        addresses.add(target_contract.lower())
        
        # 添加明确相关的地址
        if related_addresses:
            addresses.update([addr.lower() for addr in related_addresses if Web3.is_address(addr)])
        
        # 从调用图中提取地址
        if call_graph:
            for tx_data in call_graph.values():
                if isinstance(tx_data, dict) and 'related_contracts' in tx_data:
                    if isinstance(tx_data['related_contracts'], (set, list)):
                        addresses.update([addr.lower() for addr in tx_data['related_contracts']])
        
        # 从数据库交互记录中提取地址
        try:
            from sqlalchemy import and_, or_
            
            interactions = self.db.query(UserInteraction).filter(
                and_(
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block,
                    or_(
                        UserInteraction.target_contract == target_contract.lower(),
                        UserInteraction.caller_contract == target_contract.lower()
                    )
                )
            ).all()
            
            for interaction in interactions:
                addresses.add(interaction.target_contract.lower())
                addresses.add(interaction.caller_contract.lower())
        
        except Exception as e:
            print(f"从数据库提取地址时出错: {str(e)}")
        
        print(f"收集到 {len(addresses)} 个相关地址")
        return addresses
    
    def _build_address_layer(self, addresses: Set[str], start_block: int, end_block: int) -> GraphLayer:
        """构建地址层"""
        print("构建地址层...")
        
        layer = GraphLayer(
            layer_id=1,
            layer_name="Address Layer",
            node_type=NodeType.ADDRESS
        )
        
        for idx, address in enumerate(addresses, 1):
            # 确定地址类型
            address_type = self._determine_address_type(address)
            
            # 创建地址节点
            node_id = f"A{idx}"
            addr_node = AddressNode(node_id, address, address_type)
            
            # 补充合约信息
            if address_type == AddressType.CONTRACT:
                self._enrich_contract_info(addr_node, address)
            
            # 统计交易数据
            self._calculate_address_stats(addr_node, address, start_block, end_block)
            
            layer.add_node(addr_node)
        
        print(f"地址层构建完成: {layer.get_node_count()} 个节点")
        return layer
    
    def _build_transaction_layer(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int,
        related_addresses: Set[str]
    ) -> GraphLayer:
        """构建交易层"""
        print("构建交易层...")
        
        layer = GraphLayer(
            layer_id=2,
            layer_name="Transaction Layer",
            node_type=NodeType.TRANSACTION
        )
        
        try:
            from sqlalchemy import and_, or_
            
            # 查询相关交易
            address_conditions = [
                UserInteraction.target_contract.in_(list(related_addresses)),
                UserInteraction.caller_contract.in_(list(related_addresses))
            ]
            
            interactions = self.db.query(UserInteraction).filter(
                and_(
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block,
                    or_(*address_conditions)
                )
            ).all()
            
            processed_txs = set()
            
            for idx, interaction in enumerate(interactions, 1):
                tx_hash = interaction.tx_hash
                
                # 避免重复处理同一交易
                if tx_hash in processed_txs:
                    continue
                processed_txs.add(tx_hash)
                
                # 创建交易节点
                node_id = f"T{idx}"
                tx_node = TransactionNode(node_id, tx_hash)
                
                # 填充交易信息
                tx_node.properties.update({
                    "timestamp": int(interaction.timestamp.timestamp()) if interaction.timestamp else None,
                    "block_number": interaction.block_number,
                    "from_address": interaction.caller_contract.lower(),
                    "to_address": interaction.target_contract.lower(),
                    "method": interaction.method_name,
                    "method_id": interaction.input_data[:10] if interaction.input_data else None,
                    "status": "success"  # 假设成功，实际可以从trace数据获取
                })
                
                # 设置节点关系
                # 这里简化处理，in_nodes指向from地址，out_nodes指向to地址
                # 实际实现中需要根据地址层的node_id来设置
                
                layer.add_node(tx_node)
        
        except Exception as e:
            print(f"构建交易层时出错: {str(e)}")
            traceback.print_exc()
        
        print(f"交易层构建完成: {layer.get_node_count()} 个节点")
        return layer
    
    def _build_function_call_layer(self, call_graph: Dict, related_addresses: Set[str]) -> GraphLayer:
        """构建函数调用层"""
        print("构建函数调用层...")
        
        layer = GraphLayer(
            layer_id=3,
            layer_name="Function Call Layer",
            node_type=NodeType.FUNCTION_CALL
        )
        
        call_idx = 1
        
        try:
            for tx_hash, tx_data in call_graph.items():
                if not isinstance(tx_data, dict) or 'call_hierarchy' not in tx_data:
                    continue
                
                # 递归处理调用层次结构
                call_idx = self._extract_function_calls_recursive(
                    tx_data['call_hierarchy'], 
                    layer, 
                    call_idx, 
                    tx_hash,
                    related_addresses
                )
        
        except Exception as e:
            print(f"构建函数调用层时出错: {str(e)}")
            traceback.print_exc()
        
        print(f"函数调用层构建完成: {layer.get_node_count()} 个节点")
        return layer
    
    def _build_event_layer(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int,
        related_addresses: Set[str]
    ) -> GraphLayer:
        """构建事件层"""
        print("构建事件层...")
        
        layer = GraphLayer(
            layer_id=4,
            layer_name="Event Layer",
            node_type=NodeType.EVENT
        )
        
        # 这里暂时返回空层，实际实现需要解析事件日志
        # 可以从UserInteraction.event_logs字段中提取事件信息
        
        try:
            from sqlalchemy import and_, or_
            
            interactions = self.db.query(UserInteraction).filter(
                and_(
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block,
                    UserInteraction.target_contract.in_(list(related_addresses)),
                    UserInteraction.event_logs.isnot(None)
                )
            ).all()
            
            event_idx = 1
            
            for interaction in interactions:
                if interaction.event_logs:
                    try:
                        events = json.loads(interaction.event_logs)
                        if isinstance(events, list):
                            for event in events:
                                if isinstance(event, dict) and 'topics' in event:
                                    # 创建事件节点
                                    node_id = f"E{event_idx}"
                                    event_name = self._extract_event_name(event)
                                    
                                    event_node = EventNode(
                                        node_id, 
                                        event_name, 
                                        interaction.target_contract
                                    )
                                    
                                    event_node.properties.update({
                                        "tx_hash": interaction.tx_hash,
                                        "block_number": interaction.block_number,
                                        "timestamp": int(interaction.timestamp.timestamp()) if interaction.timestamp else None,
                                        "topics": event.get('topics', []),
                                        "data": event.get('data', ''),
                                        "log_index": event.get('logIndex')
                                    })
                                    
                                    layer.add_node(event_node)
                                    event_idx += 1
                    
                    except Exception as e:
                        print(f"解析事件日志时出错: {str(e)}")
                        continue
        
        except Exception as e:
            print(f"构建事件层时出错: {str(e)}")
            traceback.print_exc()
        
        print(f"事件层构建完成: {layer.get_node_count()} 个节点")
        return layer
    
    def _determine_address_type(self, address: str) -> AddressType:
        """确定地址类型（EOA或合约）"""
        if address in self.address_cache:
            return self.address_cache[address]
        
        try:
            # 检查数据库中是否有该合约的记录
            contract_info = get_contract_full_info(self.db, address)
            if contract_info:
                self.address_cache[address] = AddressType.CONTRACT
                return AddressType.CONTRACT
            
            # 如果数据库没有记录，假设是EOA（实际可以通过Web3检查）
            self.address_cache[address] = AddressType.EOA
            return AddressType.EOA
        
        except Exception as e:
            print(f"确定地址类型时出错: {str(e)}")
            self.address_cache[address] = AddressType.EOA
            return AddressType.EOA
    
    def _enrich_contract_info(self, addr_node: AddressNode, address: str):
        """丰富合约信息"""
        try:
            contract_info = get_contract_full_info(self.db, address)
            if contract_info:
                addr_node.properties.update({
                    "contract_name": contract_info.get('c_name'),
                    "is_verified": bool(contract_info.get('source_code')),
                    "proxy_info": {
                        "is_proxy": contract_info.get('is_proxy', False),
                        "parent_address": contract_info.get('parent_address')
                    } if contract_info.get('is_proxy') else None
                })
                
                # 这里暂时不设置creator和contract_code_index
                # 需要在下一步实现数据库索引时处理
        
        except Exception as e:
            print(f"丰富合约信息时出错: {str(e)}")
    
    def _calculate_address_stats(
        self, 
        addr_node: AddressNode, 
        address: str, 
        start_block: int, 
        end_block: int
    ):
        """计算地址在分析窗口内的统计信息"""
        try:
            from sqlalchemy import and_, or_, func
            
            # 查询作为调用者的交易
            outgoing = self.db.query(UserInteraction).filter(
                and_(
                    UserInteraction.caller_contract == address,
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block
                )
            ).all()
            
            # 查询作为目标的交易
            incoming = self.db.query(UserInteraction).filter(
                and_(
                    UserInteraction.target_contract == address,
                    UserInteraction.block_number >= start_block,
                    UserInteraction.block_number <= end_block
                )
            ).all()
            
            # 更新统计信息
            addr_node.properties["out_degree"] = len(outgoing)
            addr_node.properties["in_degree"] = len(incoming)
            
            # 计算时间范围
            all_interactions = outgoing + incoming
            if all_interactions:
                timestamps = [
                    int(interaction.timestamp.timestamp()) 
                    for interaction in all_interactions 
                    if interaction.timestamp
                ]
                if timestamps:
                    addr_node.properties["active_time_range"] = [min(timestamps), max(timestamps)]
            
            # 这里暂时不计算金额，因为UserInteraction表可能没有详细的value信息
            # 实际实现时可以从交易数据中提取
        
        except Exception as e:
            print(f"计算地址统计信息时出错: {str(e)}")
    
    def _extract_function_calls_recursive(
        self, 
        call_hierarchy: Dict, 
        layer: GraphLayer, 
        call_idx: int, 
        tx_hash: str,
        related_addresses: Set[str]
    ) -> int:
        """递归提取函数调用"""
        if not isinstance(call_hierarchy, dict):
            return call_idx
        
        try:
            # 提取当前调用信息
            contract_address = call_hierarchy.get('to', '').lower()
            function_name = call_hierarchy.get('method', 'unknown')
            
            if contract_address and Web3.is_address(contract_address):
                # 创建函数调用节点
                node_id = f"F{call_idx}"
                func_node = FunctionCallNode(node_id, contract_address, function_name)
                
                func_node.properties.update({
                    "caller": call_hierarchy.get('from', '').lower(),
                    "method_id": call_hierarchy.get('method_id', ''),
                    "call_type": call_hierarchy.get('call_type', 'call'),
                    "value": call_hierarchy.get('value', '0'),
                    "tx_hash": tx_hash
                })
                
                layer.add_node(func_node)
                call_idx += 1
            
            # 递归处理子调用
            children = call_hierarchy.get('children', [])
            if isinstance(children, list):
                for child in children:
                    call_idx = self._extract_function_calls_recursive(
                        child, layer, call_idx, tx_hash, related_addresses
                    )
        
        except Exception as e:
            print(f"提取函数调用时出错: {str(e)}")
        
        return call_idx
    
    def _extract_event_name(self, event: Dict) -> str:
        """从事件数据中提取事件名称"""
        # 这里简化处理，实际需要根据事件签名和ABI来解析
        topics = event.get('topics', [])
        if topics and len(topics) > 0:
            # 第一个topic是事件签名的哈希
            event_hash = topics[0]
            # 这里可以查询数据库或使用ABI来解析事件名称
            return f"Event_{event_hash[:10]}"
        return "UnknownEvent" 