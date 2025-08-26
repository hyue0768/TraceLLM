"""
图序列化器 - 将多层图转换为LLM友好的格式
基于LLM4TG格式的改进版本
"""
from typing import Dict, List, Set, Optional, Any
from .graph_layers import MultiLayerGraph, GraphLayer, NodeType, GraphNode

# 安全的值转换器 - 处理十六进制字符串等问题
def safe_float_converter(value, default=0.0):
    """安全的float转换器"""
    try:
        if value is None:
            return default
        if isinstance(value, str):
            if value.startswith('0x'):
                # 十六进制字符串转换
                if value == '0x' or value == '0x0':
                    return default
                else:
                    return float(int(value, 16))
            elif value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                return float(value)
            else:
                return default
        elif isinstance(value, (int, float)):
            return float(value)
        else:
            return default
    except (ValueError, TypeError):
        return default


class GraphSerializer:
    """图序列化器"""
    
    def __init__(self):
        self.max_property_length = 100  # 单个属性值的最大长度
        self.max_list_items = 5  # 列表属性的最大元素数量
    
    def to_llm_format(self, graph: MultiLayerGraph, max_nodes_per_layer: int = 50) -> str:
        """
        将多层图转换为LLM友好的格式
        
        格式说明：
        Layer 1: {node_count} {node_type} nodes
        {node_id} {node_type}: {properties}
        ...
        
        Layer 2: {node_count} {node_type} nodes
        ...
        """
        
        lines = []
        lines.append(f"# Ethereum Multi-Layer Transaction Graph")
        lines.append(f"# Target Contract: {graph.target_contract}")
        lines.append(f"# Time Range: {graph.time_range[0]} - {graph.time_range[1]}")
        lines.append(f"# Total Layers: {len(graph.layers)}")
        lines.append("")
        
        # 添加全局统计
        stats = graph.global_stats
        lines.append("## Global Statistics")
        lines.append(f"Total Nodes: {stats.get('total_nodes', 0)}")
        lines.append(f"Total Transactions: {stats.get('total_transactions', 0)}")
        lines.append(f"Total Contracts: {stats.get('total_contracts', 0)}")
        lines.append(f"Total Value Transferred: {stats.get('total_value_transferred', '0')} ETH")
        lines.append(f"Unique Addresses: {len(stats.get('unique_addresses', []))}")
        lines.append("")
        
        # 按layer_id排序处理各层
        sorted_layers = sorted(graph.layers.items())
        
        for layer_id, layer in sorted_layers:
            layer_lines = self._serialize_layer(layer, max_nodes_per_layer)
            lines.extend(layer_lines)
            lines.append("")  # 层之间空行
        
        return "\n".join(lines)
    
    def _serialize_layer(self, layer: GraphLayer, max_nodes: int) -> List[str]:
        """序列化单个图层"""
        lines = []
        
        # 层级标题
        lines.append(f"Layer {layer.layer_id}: {layer.get_node_count()} {layer.node_type.value} nodes")
        
        # 如果节点数超过限制，进行采样
        nodes_to_serialize = list(layer.nodes.values())
        if len(nodes_to_serialize) > max_nodes:
            # 优先保留重要节点（根据度数或其他指标）
            nodes_to_serialize = self._sample_important_nodes(nodes_to_serialize, max_nodes)
            lines.append(f"# Showing top {len(nodes_to_serialize)} most important nodes")
        
        # 序列化每个节点
        for node in nodes_to_serialize:
            node_line = self._serialize_node(node)
            lines.append(node_line)
        
        return lines
    
    def _serialize_node(self, node: GraphNode) -> str:
        """序列化单个节点"""
        # 格式: {node_id} {node_type}: {properties}
        properties_str = self._serialize_properties(node.properties, node.node_type)
        
        # 添加边信息
        if node.in_nodes or node.out_nodes:
            edge_info = []
            if node.in_nodes:
                in_nodes_str = self._truncate_list(node.in_nodes, self.max_list_items)
                edge_info.append(f"in_nodes: [{in_nodes_str}]")
            if node.out_nodes:
                out_nodes_str = self._truncate_list(node.out_nodes, self.max_list_items)
                edge_info.append(f"out_nodes: [{out_nodes_str}]")
            
            if edge_info:
                properties_str += f", {', '.join(edge_info)}"
        
        return f"{node.node_id} {node.node_type.value}: {{{properties_str}}}"
    
    def _serialize_properties(self, properties: Dict[str, Any], node_type: NodeType) -> str:
        """序列化节点属性"""
        # 根据节点类型，选择最重要的属性
        important_props = self._get_important_properties(node_type)
        
        prop_parts = []
        
        for prop_name in important_props:
            if prop_name in properties:
                value = properties[prop_name]
                if value is not None:
                    serialized_value = self._serialize_value(value)
                    prop_parts.append(f"{prop_name}: {serialized_value}")
        
        # 添加其他重要属性（如果还有空间）
        other_props = [k for k in properties.keys() if k not in important_props]
        remaining_space = 5 - len(prop_parts)  # 最多显示5个属性
        
        for prop_name in other_props[:remaining_space]:
            value = properties[prop_name]
            if value is not None and value != "" and value != 0:
                serialized_value = self._serialize_value(value)
                prop_parts.append(f"{prop_name}: {serialized_value}")
        
        return ", ".join(prop_parts)
    
    def _get_important_properties(self, node_type: NodeType) -> List[str]:
        """获取不同节点类型的重要属性列表"""
        if node_type == NodeType.ADDRESS:
            return ["address", "address_type", "in_degree", "out_degree", "in_value", "out_value", "contract_name"]
        
        elif node_type == NodeType.TRANSACTION:
            return ["hash", "from_address", "to_address", "value", "method", "timestamp", "status"]
        
        elif node_type == NodeType.FUNCTION_CALL:
            return ["contract_address", "function_name", "caller", "call_type", "value", "call_depth"]
        
        elif node_type == NodeType.EVENT:
            return ["event_name", "contract_address", "tx_hash", "block_number"]
        
        elif node_type == NodeType.TOKEN_TRANSFER:
            return ["token_symbol", "from_address", "to_address", "amount_decimal", "transfer_type"]
        
        else:
            return []
    
    def _serialize_value(self, value: Any) -> str:
        """序列化单个值"""
        if isinstance(value, str):
            # 截断过长的字符串
            if len(value) > self.max_property_length:
                return f'"{value[:self.max_property_length]}..."'
            return f'"{value}"'
        
        elif isinstance(value, (int, float)):
            return str(value)
        
        elif isinstance(value, bool):
            return str(value).lower()
        
        elif isinstance(value, list):
            if len(value) == 0:
                return "[]"
            truncated = self._truncate_list(value, self.max_list_items)
            return f"[{truncated}]"
        
        elif isinstance(value, dict):
            if len(value) == 0:
                return "{}"
            # 只显示最重要的键值对
            important_items = list(value.items())[:3]
            items_str = ", ".join([f"{k}: {self._serialize_value(v)}" for k, v in important_items])
            if len(value) > 3:
                items_str += ", ..."
            return f"{{{items_str}}}"
        
        elif value is None:
            return "null"
        
        else:
            return f'"{str(value)}"'
    
    def _truncate_list(self, items: List[Any], max_items: int) -> str:
        """截断列表并返回字符串表示"""
        if len(items) <= max_items:
            return ", ".join([f'"{str(item)}"' for item in items])
        else:
            truncated = items[:max_items]
            truncated_str = ", ".join([f'"{str(item)}"' for item in truncated])
            return f"{truncated_str}, ... (+{len(items) - max_items} more)"
    
    def _sample_important_nodes(self, nodes: List[GraphNode], max_nodes: int) -> List[GraphNode]:
        """采样重要节点"""
        # 根据节点类型和重要性进行采样
        def get_node_importance(node: GraphNode) -> float:
            importance = 0.0
            
            # 基于度数的重要性
            in_degree = len(node.in_nodes)
            out_degree = len(node.out_nodes)
            importance += (in_degree + out_degree) * 0.1
            
            # 基于节点类型的重要性
            if node.node_type == NodeType.ADDRESS:
                # 合约地址比EOA更重要
                if node.properties.get("address_type") == "Contract":
                    importance += 10.0
                # 有名称的合约更重要
                if node.properties.get("contract_name"):
                    importance += 5.0
                # 交易量大的地址更重要
                total_value = safe_float_converter(node.properties.get("in_value", "0")) + safe_float_converter(node.properties.get("out_value", "0"))
                importance += min(total_value / 1e18, 100)  # 按ETH计算，最多加100分
            
            elif node.node_type == NodeType.TRANSACTION:
                # 大额交易更重要
                value = safe_float_converter(node.properties.get("value", "0"))
                importance += min(value / 1e18, 50)  # 最多加50分
                # 有方法调用的交易更重要
                if node.properties.get("method") and node.properties.get("method") != "transfer":
                    importance += 5.0
            
            elif node.node_type == NodeType.FUNCTION_CALL:
                # 复杂调用更重要
                call_depth = node.properties.get("call_depth", 0)
                importance += call_depth * 2.0
                # 有价值转移的调用更重要
                value = safe_float_converter(node.properties.get("value", "0"))
                importance += min(value / 1e18, 20)
            
            return importance
        
        # 按重要性排序并取前max_nodes个
        nodes_with_importance = [(node, get_node_importance(node)) for node in nodes]
        nodes_with_importance.sort(key=lambda x: x[1], reverse=True)
        
        return [node for node, _ in nodes_with_importance[:max_nodes]]
    
    def to_json(self, graph: MultiLayerGraph) -> Dict[str, Any]:
        """将图转换为JSON格式"""
        return graph.to_dict()
    
    def to_compact_format(self, graph: MultiLayerGraph, max_total_nodes: int = 100) -> str:
        """
        转换为紧凑格式，适用于token限制严格的场景
        """
        lines = []
        lines.append(f"Graph: {graph.target_contract} [{graph.time_range[0]}-{graph.time_range[1]}]")
        
        # 计算每层的节点配额
        total_layers = len(graph.layers)
        nodes_per_layer = max_total_nodes // total_layers if total_layers > 0 else max_total_nodes
        
        for layer_id, layer in sorted(graph.layers.items()):
            if layer.get_node_count() == 0:
                continue
                
            lines.append(f"L{layer_id}({layer.node_type.value}): {layer.get_node_count()}")
            
            # 采样节点
            nodes = self._sample_important_nodes(list(layer.nodes.values()), nodes_per_layer)
            
            for node in nodes:
                compact_line = self._serialize_node_compact(node)
                lines.append(f"  {compact_line}")
        
        return "\n".join(lines)
    
    def _serialize_node_compact(self, node: GraphNode) -> str:
        """序列化节点为紧凑格式"""
        # 只保留最关键的信息
        if node.node_type == NodeType.ADDRESS:
            addr = node.properties.get("address", "")[:10]  # 只显示地址前10位
            addr_type = node.properties.get("address_type", "")
            name = node.properties.get("contract_name", "")
            if name:
                return f"{node.node_id}({addr_type}): {addr}...[{name}]"
            else:
                return f"{node.node_id}({addr_type}): {addr}..."
        
        elif node.node_type == NodeType.TRANSACTION:
            tx_hash = node.properties.get("hash", "")[:10]
            method = node.properties.get("method", "")
            value = node.properties.get("value", "0")
            return f"{node.node_id}: {tx_hash}...[{method}, {value}]"
        
        elif node.node_type == NodeType.FUNCTION_CALL:
            func_name = node.properties.get("function_name", "")
            contract = node.properties.get("contract_address", "")[:10]
            return f"{node.node_id}: {func_name}@{contract}..."
        
        else:
            return f"{node.node_id}: {node.node_type.value}" 