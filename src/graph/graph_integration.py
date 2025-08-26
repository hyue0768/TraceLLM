"""
图集成模块 - 将新的多层图结构集成到现有分析系统中
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from typing import Dict, List, Optional, Any
from .graph_builder import GraphBuilder
from .graph_layers import MultiLayerGraph, NodeType
from analyze_user_behavior import build_transaction_call_graph

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


class GraphIntegrator:
    """图集成器 - 将多层图结构集成到现有分析流程中"""
    
    def __init__(self):
        self.graph_builder = GraphBuilder()
    
    def build_enhanced_analysis_graph(
        self,
        target_contract: str,
        start_block: int,
        end_block: int,
        related_addresses: List[str] = None,
        analysis_type: str = "full"
    ) -> MultiLayerGraph:
        """
        构建增强的分析图，替代原有的调用图
        
        Args:
            target_contract: 目标合约地址
            start_block: 开始区块
            end_block: 结束区块
            related_addresses: 相关地址列表
            analysis_type: 分析类型 ("full", "security", "transfer", "compact")
        
        Returns:
            MultiLayerGraph: 多层图对象
        """
        
        print(f"开始构建增强分析图: {analysis_type} 模式")
        
        # 1. 首先使用原有方法构建调用图
        call_graph = build_transaction_call_graph(
            target_contract,
            start_block,
            end_block,
            max_depth=3,
            pruning_enabled=True,
            related_addresses=related_addresses
        )
        
        # 2. 根据分析类型选择要包含的图层
        include_layers = self._get_layers_for_analysis_type(analysis_type)
        
        # 3. 构建多层图
        multilayer_graph = self.graph_builder.build_multilayer_graph(
            target_contract=target_contract,
            start_block=start_block,
            end_block=end_block,
            related_addresses=related_addresses,
            call_graph=call_graph,
            include_layers=include_layers
        )
        
        return multilayer_graph
    
    def _get_layers_for_analysis_type(self, analysis_type: str) -> List[NodeType]:
        """根据分析类型确定需要包含的图层"""
        
        if analysis_type == "full":
            # 完整分析：包含所有层
            return [
                NodeType.ADDRESS,
                NodeType.TRANSACTION,
                NodeType.FUNCTION_CALL,
                NodeType.EVENT
            ]
        
        elif analysis_type == "security":
            # 安全分析：重点关注地址、交易和函数调用
            return [
                NodeType.ADDRESS,
                NodeType.TRANSACTION,
                NodeType.FUNCTION_CALL
            ]
        
        elif analysis_type == "transfer":
            # 转账分析：重点关注地址和交易
            return [
                NodeType.ADDRESS,
                NodeType.TRANSACTION
            ]
        
        elif analysis_type == "compact":
            # 紧凑模式：只包含地址层
            return [
                NodeType.ADDRESS
            ]
        
        else:
            # 默认：地址和交易层
            return [
                NodeType.ADDRESS,
                NodeType.TRANSACTION
            ]
    
    def get_llm_friendly_graph_data(
        self,
        multilayer_graph: MultiLayerGraph,
        format_type: str = "standard",
        max_nodes_per_layer: int = 30
    ) -> str:
        """
        获取LLM友好的图数据格式
        
        Args:
            multilayer_graph: 多层图对象
            format_type: 格式类型 ("standard", "compact", "focused")
            max_nodes_per_layer: 每层最大节点数
        
        Returns:
            str: 格式化的图数据字符串
        """
        
        if format_type == "compact":
            return multilayer_graph.to_llm_format(max_nodes_per_layer=20)
        
        elif format_type == "focused":
            # 专注模式：只显示最重要的信息
            return self._create_focused_format(multilayer_graph)
        
        else:
            # 标准模式
            return multilayer_graph.to_llm_format(max_nodes_per_layer)
    
    def _create_focused_format(self, graph: MultiLayerGraph) -> str:
        """创建专注格式，突出最重要的信息"""
        
        lines = []
        lines.append(f"# 重点分析：{graph.target_contract}")
        lines.append(f"# 区块范围：{graph.time_range[0]} - {graph.time_range[1]}")
        lines.append("")
        
        # 重点关注的合约地址
        address_layer = graph.get_layer(1)  # 地址层
        if address_layer:
            important_contracts = []
            for node in address_layer.nodes.values():
                if node.properties.get("address_type") == "Contract":
                    contract_name = node.properties.get("contract_name", "未知合约")
                    in_degree = node.properties.get("in_degree", 0)
                    out_degree = node.properties.get("out_degree", 0)
                    
                    importance_score = in_degree + out_degree
                    if node.properties.get("contract_name"):
                        importance_score += 10  # 有名称的合约更重要
                    
                    important_contracts.append({
                        "address": node.properties["address"],
                        "name": contract_name,
                        "score": importance_score,
                        "in_degree": in_degree,
                        "out_degree": out_degree
                    })
            
            # 按重要性排序
            important_contracts.sort(key=lambda x: x["score"], reverse=True)
            
            lines.append("## 重要合约地址")
            for i, contract in enumerate(important_contracts[:5], 1):
                lines.append(f"{i}. {contract['name']} ({contract['address'][:10]}...)")
                lines.append(f"   - 交互次数：入{contract['in_degree']}次，出{contract['out_degree']}次")
            lines.append("")
        
        # 关键交易信息
        tx_layer = graph.get_layer(2)  # 交易层
        if tx_layer:
            lines.append("## 关键交易")
            tx_count = 0
            for node in tx_layer.nodes.values():
                if tx_count >= 3:  # 只显示前3个重要交易
                    break
                
                tx_hash = node.properties.get("hash", "")
                method = node.properties.get("method", "")
                value = node.properties.get("value", "0")
                
                lines.append(f"{tx_count + 1}. 交易：{tx_hash[:10]}...")
                lines.append(f"   - 方法：{method}")
                lines.append(f"   - 金额：{value} wei")
                tx_count += 1
            lines.append("")
        
        # 全局统计
        stats = graph.global_stats
        lines.append("## 整体统计")
        lines.append(f"总交易数：{stats.get('total_transactions', 0)}")
        lines.append(f"涉及合约数：{stats.get('total_contracts', 0)}")
        lines.append(f"总转账金额：{stats.get('total_value_transferred', '0')} wei")
        
        return "\n".join(lines)
    
    def extract_graph_summary_for_llm(self, multilayer_graph: MultiLayerGraph) -> Dict[str, Any]:
        """
        提取图的关键信息摘要，用于LLM分析
        
        Returns:
            Dict: 包含关键信息的字典
        """
        
        summary = {
            "target_contract": multilayer_graph.target_contract,
            "time_range": multilayer_graph.time_range,
            "global_stats": multilayer_graph.global_stats.copy(),
            "layer_summary": {},
            "key_findings": []
        }
        
        # 确保unique_addresses可序列化
        if "unique_addresses" in summary["global_stats"]:
            summary["global_stats"]["unique_addresses"] = list(summary["global_stats"]["unique_addresses"])
        
        # 各层摘要
        for layer_id, layer in multilayer_graph.layers.items():
            layer_info = {
                "layer_name": layer.layer_name,
                "node_type": layer.node_type.value,
                "node_count": layer.get_node_count(),
                "top_nodes": []
            }
            
            # 提取每层的关键节点
            if layer.node_type == NodeType.ADDRESS:
                # 地址层：找出最活跃的地址
                addresses_by_activity = []
                for node in layer.nodes.values():
                    total_activity = node.properties.get("in_degree", 0) + node.properties.get("out_degree", 0)
                    addresses_by_activity.append({
                        "address": node.properties.get("address", ""),
                        "activity": total_activity,
                        "type": node.properties.get("address_type", ""),
                        "name": node.properties.get("contract_name", "")
                    })
                
                addresses_by_activity.sort(key=lambda x: x["activity"], reverse=True)
                layer_info["top_nodes"] = addresses_by_activity[:5]
            
            elif layer.node_type == NodeType.TRANSACTION:
                # 交易层：找出高价值交易
                txs_by_value = []
                for node in layer.nodes.values():
                    value = safe_float_converter(node.properties.get("value", "0"))
                    txs_by_value.append({
                        "hash": node.properties.get("hash", ""),
                        "value": value,
                        "method": node.properties.get("method", ""),
                        "from": node.properties.get("from_address", ""),
                        "to": node.properties.get("to_address", "")
                    })
                
                txs_by_value.sort(key=lambda x: x["value"], reverse=True)
                layer_info["top_nodes"] = txs_by_value[:5]
            
            summary["layer_summary"][layer_id] = layer_info
        
        # 关键发现
        summary["key_findings"] = self._extract_key_findings(multilayer_graph)
        
        return summary
    
    def _extract_key_findings(self, graph: MultiLayerGraph) -> List[str]:
        """提取关键发现"""
        
        findings = []
        
        # 检查是否有大量交易
        total_txs = graph.global_stats.get("total_transactions", 0)
        if total_txs > 100:
            findings.append(f"发现大量交易活动：{total_txs}笔交易")
        
        # 检查是否有高价值转账
        total_value = safe_float_converter(graph.global_stats.get("total_value_transferred", "0"))
        if total_value > 1e18:  # 超过1 ETH
            eth_value = total_value / 1e18
            findings.append(f"发现高价值转账：总计{eth_value:.2f} ETH")
        
        # 检查合约数量
        total_contracts = graph.global_stats.get("total_contracts", 0)
        if total_contracts > 10:
            findings.append(f"涉及多个合约：{total_contracts}个合约")
        
        # 检查是否有未验证合约
        address_layer = graph.get_layer(1)
        if address_layer:
            unverified_contracts = 0
            for node in address_layer.nodes.values():
                if (node.properties.get("address_type") == "Contract" and 
                    not node.properties.get("is_verified", False)):
                    unverified_contracts += 1
            
            if unverified_contracts > 0:
                findings.append(f"发现{unverified_contracts}个未验证合约")
        
        return findings


def integrate_multilayer_graph_to_analysis(
    target_contract: str,
    start_block: int,
    end_block: int,
    related_addresses: List[str] = None,
    analysis_mode: str = "security"
) -> str:
    """
    集成多层图到现有分析流程的便捷函数
    
    这个函数可以直接替代原有的调用图构建过程
    """
    
    integrator = GraphIntegrator()
    
    # 构建多层图
    multilayer_graph = integrator.build_enhanced_analysis_graph(
        target_contract=target_contract,
        start_block=start_block,
        end_block=end_block,
        related_addresses=related_addresses,
        analysis_type=analysis_mode
    )
    
    # 获取LLM友好格式
    if analysis_mode == "security":
        graph_data = integrator.get_llm_friendly_graph_data(
            multilayer_graph, 
            format_type="focused", 
            max_nodes_per_layer=20
        )
    else:
        graph_data = integrator.get_llm_friendly_graph_data(
            multilayer_graph, 
            format_type="standard", 
            max_nodes_per_layer=30
        )
    
    return graph_data 