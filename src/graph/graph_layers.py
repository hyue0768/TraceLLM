"""
以太坊多层交易图的核心结构定义
基于LLM4TG格式的改进版本，适配以太坊生态
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Any, Union
from enum import Enum
import json
from decimal import Decimal


class NodeType(Enum):
    """节点类型枚举"""
    ADDRESS = "address"
    TRANSACTION = "transaction"
    FUNCTION_CALL = "function_call"
    EVENT = "event"
    TOKEN_TRANSFER = "token_transfer"


class AddressType(Enum):
    """地址类型枚举"""
    EOA = "EOA"  # 外部拥有账户
    CONTRACT = "Contract"  # 合约账户


@dataclass
class GraphNode:
    """图节点基类"""
    node_id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)
    in_nodes: List[str] = field(default_factory=list)
    out_nodes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "properties": self.properties,
            "in_nodes": self.in_nodes,
            "out_nodes": self.out_nodes
        }


@dataclass
class AddressNode(GraphNode):
    """地址节点"""
    
    def __init__(self, node_id: str, address: str, address_type: AddressType):
        super().__init__(node_id, NodeType.ADDRESS)
        self.properties.update({
            "address": address.lower(),
            "address_type": address_type.value,
            "in_degree": 0,
            "out_degree": 0,
            "in_value": "0",  # 本分析窗口内的入金额（字符串形式，支持大数）
            "out_value": "0",  # 本分析窗口内的出金额
            "active_time_range": None,  # 活跃时间范围 [start_timestamp, end_timestamp]
            "contract_name": None,  # 合约名称（如果是合约）
            "creator": None,  # 创建者地址（如果是合约）
            "contract_code_index": None,  # 数据库中源码的索引（后续实现）
            "is_verified": False,  # 是否已验证合约
            "proxy_info": None  # 代理合约信息
        })
    
    def update_transaction_stats(self, value: str, is_incoming: bool, timestamp: int):
        """更新交易统计信息"""
        if is_incoming:
            self.properties["in_degree"] += 1
            current_in = Decimal(self.properties["in_value"])
            self.properties["in_value"] = str(current_in + Decimal(value))
        else:
            self.properties["out_degree"] += 1
            current_out = Decimal(self.properties["out_value"])
            self.properties["out_value"] = str(current_out + Decimal(value))
        
        # 更新活跃时间范围
        if self.properties["active_time_range"] is None:
            self.properties["active_time_range"] = [timestamp, timestamp]
        else:
            self.properties["active_time_range"][0] = min(self.properties["active_time_range"][0], timestamp)
            self.properties["active_time_range"][1] = max(self.properties["active_time_range"][1], timestamp)


@dataclass
class TransactionNode(GraphNode):
    """交易节点"""
    
    def __init__(self, node_id: str, tx_hash: str):
        super().__init__(node_id, NodeType.TRANSACTION)
        self.properties.update({
            "hash": tx_hash,
            "timestamp": None,
            "block_number": None,
            "from_address": None,
            "to_address": None,
            "value": "0",  # ETH转账金额
            "gas_used": None,
            "gas_price": None,
            "method": None,  # 调用的方法名
            "method_id": None,  # 方法选择器
            "status": None,  # 交易状态 (success/failed)
            "transaction_type": "transfer",  # transfer/contract_call/contract_creation
            "error_message": None  # 错误信息（如果失败）
        })


@dataclass
class FunctionCallNode(GraphNode):
    """函数调用节点"""
    
    def __init__(self, node_id: str, contract_address: str, function_name: str):
        super().__init__(node_id, NodeType.FUNCTION_CALL)
        self.properties.update({
            "contract_address": contract_address.lower(),
            "function_name": function_name,
            "function_signature": None,  # 完整的函数签名
            "params": None,  # 参数摘要（不存储完整参数以节省空间）
            "caller": None,  # 调用者地址
            "call_depth": 0,  # 调用深度
            "call_type": "call",  # call/delegatecall/staticcall/create
            "value": "0",  # 调用附带的ETH金额
            "gas_limit": None,
            "gas_used": None,
            "return_data": None,  # 返回数据摘要
            "code_index": None,  # 数据库中函数源码的索引（后续实现）
            "is_internal": False,  # 是否为内部调用
            "error": None  # 调用错误信息
        })


@dataclass
class EventNode(GraphNode):
    """事件节点"""
    
    def __init__(self, node_id: str, event_name: str, contract_address: str):
        super().__init__(node_id, NodeType.EVENT)
        self.properties.update({
            "event_name": event_name,
            "contract_address": contract_address.lower(),
            "event_signature": None,  # 事件签名
            "topics": [],  # 事件topics
            "data": None,  # 事件data摘要
            "tx_hash": None,  # 所属交易哈希
            "log_index": None,  # 在交易中的日志索引
            "block_number": None,
            "timestamp": None
        })


@dataclass
class TokenTransferNode(GraphNode):
    """代币转账节点"""
    
    def __init__(self, node_id: str, token_address: str, from_addr: str, to_addr: str):
        super().__init__(node_id, NodeType.TOKEN_TRANSFER)
        self.properties.update({
            "token_address": token_address.lower(),
            "token_symbol": None,  # 代币符号
            "token_name": None,  # 代币名称
            "token_decimals": None,  # 代币精度
            "from_address": from_addr.lower(),
            "to_address": to_addr.lower(),
            "amount": "0",  # 转账金额（原始值，未考虑精度）
            "amount_decimal": "0",  # 转账金额（考虑精度后的值）
            "tx_hash": None,  # 所属交易哈希
            "log_index": None,  # 在交易中的日志索引
            "block_number": None,
            "timestamp": None,
            "transfer_type": "ERC20"  # ERC20/ERC721/ERC1155
        })


@dataclass
class GraphLayer:
    """图层定义"""
    layer_id: int
    layer_name: str
    node_type: NodeType
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    
    def add_node(self, node: GraphNode):
        """添加节点到该层"""
        self.nodes[node.node_id] = node
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取指定节点"""
        return self.nodes.get(node_id)
    
    def get_node_count(self) -> int:
        """获取节点数量"""
        return len(self.nodes)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "node_type": self.node_type.value,
            "node_count": self.get_node_count(),
            "nodes": {node_id: node.to_dict() for node_id, node in self.nodes.items()}
        }


@dataclass
class MultiLayerGraph:
    """多层图结构"""
    graph_id: str
    target_contract: str
    time_range: List[int]  # [start_block, end_block] 或 [start_timestamp, end_timestamp]
    layers: Dict[int, GraphLayer] = field(default_factory=dict)
    global_stats: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """初始化后处理"""
        self.global_stats = {
            "total_nodes": 0,
            "total_transactions": 0,
            "total_contracts": 0,
            "total_value_transferred": "0",
            "unique_addresses": set(),
            "analysis_summary": {}
        }
    
    def add_layer(self, layer: GraphLayer):
        """添加图层"""
        self.layers[layer.layer_id] = layer
        self._update_global_stats()
    
    def get_layer(self, layer_id: int) -> Optional[GraphLayer]:
        """获取指定图层"""
        return self.layers.get(layer_id)
    
    def get_all_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        """获取指定类型的所有节点"""
        nodes = []
        for layer in self.layers.values():
            if layer.node_type == node_type:
                nodes.extend(layer.nodes.values())
        return nodes
    
    def _update_global_stats(self):
        """更新全局统计信息"""
        total_nodes = 0
        unique_addresses = set()
        total_value = Decimal("0")
        
        for layer in self.layers.values():
            total_nodes += layer.get_node_count()
            
            # 统计不同类型节点的信息
            if layer.node_type == NodeType.ADDRESS:
                for node in layer.nodes.values():
                    unique_addresses.add(node.properties["address"])
                    if node.properties["address_type"] == AddressType.CONTRACT.value:
                        self.global_stats["total_contracts"] = self.global_stats.get("total_contracts", 0) + 1
            
            elif layer.node_type == NodeType.TRANSACTION:
                self.global_stats["total_transactions"] = layer.get_node_count()
                for node in layer.nodes.values():
                    total_value += Decimal(node.properties.get("value", "0"))
        
        self.global_stats.update({
            "total_nodes": total_nodes,
            "total_value_transferred": str(total_value),
            "unique_addresses": unique_addresses
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        # 确保unique_addresses是可序列化的
        stats = self.global_stats.copy()
        stats["unique_addresses"] = list(stats["unique_addresses"])
        
        return {
            "graph_id": self.graph_id,
            "target_contract": self.target_contract,
            "time_range": self.time_range,
            "layers": {layer_id: layer.to_dict() for layer_id, layer in self.layers.items()},
            "global_stats": stats
        }
    
    def to_llm_format(self, max_nodes_per_layer: int = 50) -> str:
        """转换为LLM友好的格式"""
        from .graph_serializer import GraphSerializer
        serializer = GraphSerializer()
        return serializer.to_llm_format(self, max_nodes_per_layer)
    
    def to_legacy_call_graph_format(self) -> Dict[str, Any]:
        """
        转换为传统调用图格式，保持与现有系统的兼容性
        
        Returns:
            Dict: 兼容原有 build_transaction_call_graph 返回格式的字典
        """
        legacy_call_graph = {}
        
        # 获取交易层数据
        tx_layer = self.get_layer(2)  # 交易层
        if not tx_layer:
            return legacy_call_graph
        
        # 为每个交易构建传统格式的调用图条目
        for tx_node in tx_layer.nodes.values():
            tx_hash = tx_node.properties.get("hash", "")
            if not tx_hash:
                continue
            
            # 构建传统格式的交易数据
            legacy_tx_data = {
                "related_contracts": set(),
                "call_hierarchy": {
                    "from": tx_node.properties.get("from_address", ""),
                    "to": tx_node.properties.get("to_address", ""),
                    "method": tx_node.properties.get("method", ""),
                    "value": tx_node.properties.get("value", "0"),
                    "children": []
                },
                "transaction_type": tx_node.properties.get("transaction_type", "transfer"),
                "block_number": tx_node.properties.get("block_number"),
                "timestamp": tx_node.properties.get("timestamp"),
                "status": tx_node.properties.get("status", "success")
            }
            
            # 从地址层收集相关合约
            address_layer = self.get_layer(1)  # 地址层
            if address_layer:
                for addr_node in address_layer.nodes.values():
                    addr = addr_node.properties.get("address", "")
                    if addr and addr_node.properties.get("address_type") == "Contract":
                        legacy_tx_data["related_contracts"].add(addr)
            
            # 从函数调用层构建调用层次结构
            call_layer = self.get_layer(3)  # 函数调用层
            if call_layer:
                # 查找与此交易相关的函数调用
                tx_calls = []
                for call_node in call_layer.nodes.values():
                    # 这里需要根据实际的关联逻辑来匹配
                    # 暂时简化处理
                    call_info = {
                        "from": call_node.properties.get("caller", ""),
                        "to": call_node.properties.get("contract_address", ""),
                        "method": call_node.properties.get("function_name", ""),
                        "value": call_node.properties.get("value", "0"),
                        "children": []
                    }
                    tx_calls.append(call_info)
                
                # 将函数调用添加到调用层次结构中
                if tx_calls:
                    legacy_tx_data["call_hierarchy"]["children"] = tx_calls
            
            # 转换set为list以便JSON序列化
            legacy_tx_data["related_contracts"] = list(legacy_tx_data["related_contracts"])
            
            legacy_call_graph[tx_hash] = legacy_tx_data
        
        return legacy_call_graph


def ensure_json_serializable(obj):
    """确保对象可以被JSON序列化"""
    if isinstance(obj, dict):
        return {k: ensure_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [ensure_json_serializable(item) for item in obj]
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, Decimal):
        return str(obj)
    elif isinstance(obj, Enum):
        return obj.value
    else:
        return obj 