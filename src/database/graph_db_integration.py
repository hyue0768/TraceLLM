"""
数据库和多层图系统的集成模块
提供高性能的数据查询、缓存和索引功能
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from decimal import Decimal

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from .enhanced_models import (
    IndexedDataAccess, 
    ContractSourceIndex, 
    FunctionSignatureIndex,
    EventSignatureIndex, 
    ContractCreatorIndex,
    AddressLabelIndex, 
    TokenInfoIndex,
    MultiLayerGraphCache,
    generate_graph_cache_key
)
from ..graph.graph_layers import MultiLayerGraph, AddressNode, AddressType
from ..graph.graph_builder import GraphBuilder
from ..graph.graph_serializer import GraphSerializer


class GraphDatabaseIntegrator:
    """多层图和数据库的集成器"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.data_access = IndexedDataAccess(db_session)
        self.graph_builder = GraphBuilder()
        self.graph_serializer = GraphSerializer()
        
        # 缓存配置
        self.cache_expire_hours = 24  # 缓存过期时间
        self.max_cache_entries = 1000  # 最大缓存条目数
    
    def build_enhanced_multilayer_graph(
        self,
        target_contract: str,
        start_block: int,
        end_block: int,
        analysis_type: str = "full",
        use_cache: bool = True,
        related_addresses: List[str] = None
    ) -> MultiLayerGraph:
        """构建增强的多层图，集成数据库索引信息"""
        
        # 1. 检查缓存
        if use_cache:
            cache_key = generate_graph_cache_key(
                target_contract, start_block, end_block, analysis_type
            )
            cached_graph = self._get_cached_graph(cache_key)
            if cached_graph:
                print(f"使用缓存的多层图数据: {cache_key}")
                return cached_graph
        
        # 2. 构建基础图结构
        print("构建基础多层图结构...")
        multilayer_graph = self.graph_builder.build_multilayer_graph(
            target_contract=target_contract,
            start_block=start_block,
            end_block=end_block,
            related_addresses=related_addresses
        )
        
        # 3. 增强地址层信息
        print("增强地址层信息...")
        self._enrich_address_layer(multilayer_graph)
        
        # 4. 增强函数调用层信息
        print("增强函数调用层信息...")
        self._enrich_function_call_layer(multilayer_graph)
        
        # 5. 增强事件层信息
        print("增强事件层信息...")
        self._enrich_event_layer(multilayer_graph)
        
        # 6. 缓存结果
        if use_cache:
            self._cache_graph(cache_key, multilayer_graph, analysis_type)
        
        return multilayer_graph
    
    def _enrich_address_layer(self, graph: MultiLayerGraph):
        """增强地址层信息，添加索引数据"""
        address_layer = graph.get_layer(1)  # 地址层通常是第1层
        if not address_layer:
            return
        
        for node_id, address_node in address_layer.nodes.items():
            address = address_node.properties.get("address")
            if not address:
                continue
            
            # 获取合约源码信息
            source_info = self.data_access.get_contract_source_by_address(address)
            if source_info:
                address_node.properties.update({
                    "contract_name": source_info.contract_name,
                    "verification_status": source_info.verification_status,
                    "compiler_version": source_info.compiler_version,
                    "contract_code_index": source_info.source_code_index,
                    "abi_index": source_info.abi_index,
                    "is_verified": source_info.verification_status == "verified"
                })
            
            # 获取创建者信息
            creator_info = self.data_access.get_contract_creator(address)
            if creator_info:
                address_node.properties.update({
                    "creator": creator_info.creator_address,
                    "creation_block": creator_info.creation_block_number,
                    "creation_timestamp": creator_info.creation_timestamp.timestamp() if creator_info.creation_timestamp else None,
                    "factory_contract": creator_info.factory_contract,
                    "creation_method": creator_info.creation_method
                })
            
            # 获取地址标签
            labels = self.data_access.get_address_labels(address)
            if labels:
                address_node.properties["labels"] = [
                    {
                        "type": label.label_type,
                        "name": label.label_name,
                        "source": label.label_source,
                        "confidence": float(label.confidence_score),
                        "verified": label.verified
                    }
                    for label in labels
                ]
            
            # 获取代币信息（如果是代币合约）
            token_info = self.data_access.get_token_info(address)
            if token_info:
                address_node.properties.update({
                    "token_symbol": token_info.token_symbol,
                    "token_name": token_info.token_name,
                    "token_decimals": token_info.token_decimals,
                    "token_type": token_info.token_type,
                    "token_total_supply": token_info.token_total_supply,
                    "is_mintable": token_info.is_mintable,
                    "is_burnable": token_info.is_burnable,
                    "is_pausable": token_info.is_pausable
                })
    
    def _enrich_function_call_layer(self, graph: MultiLayerGraph):
        """增强函数调用层信息"""
        function_call_layer = graph.get_layer(3)  # 函数调用层通常是第3层
        if not function_call_layer:
            return
        
        for node_id, call_node in function_call_layer.nodes.items():
            # 从函数名构造选择器（简化实现）
            function_name = call_node.properties.get("function_name")
            if function_name and function_name != "unknown":
                # 这里应该从更准确的数据源获取选择器
                # 暂时使用函数名的哈希前8位作为示例
                selector_hash = hashlib.sha3_256(function_name.encode()).hexdigest()[:8]
                selector = f"0x{selector_hash}"
                
                # 查询函数签名信息
                sig_info = self.data_access.get_function_by_selector(selector)
                if sig_info:
                    call_node.properties.update({
                        "function_signature": sig_info.function_signature,
                        "parameter_types": sig_info.parameter_types,
                        "usage_count": sig_info.usage_count,
                        "code_index": sig_info.source_contract  # 简化映射
                    })
    
    def _enrich_event_layer(self, graph: MultiLayerGraph):
        """增强事件层信息"""
        event_layer = graph.get_layer(4)  # 事件层通常是第4层
        if not event_layer:
            return
        
        for node_id, event_node in event_layer.nodes.items():
            event_name = event_node.properties.get("event_name")
            if event_name:
                # 构造事件topic0（简化实现）
                topic0_hash = hashlib.sha3_256(f"{event_name}()".encode()).hexdigest()
                topic0 = f"0x{topic0_hash}"
                
                # 查询事件签名信息
                event_info = self.data_access.get_event_by_topic0(topic0)
                if event_info:
                    event_node.properties.update({
                        "event_signature": event_info.event_signature,
                        "indexed_params": event_info.indexed_params,
                        "non_indexed_params": event_info.non_indexed_params,
                        "usage_count": event_info.usage_count
                    })
    
    def _get_cached_graph(self, cache_key: str) -> Optional[MultiLayerGraph]:
        """获取缓存的图数据"""
        try:
            cached = self.data_access.get_cached_graph(cache_key)
            if cached:
                # 更新访问计数
                self.data_access.update_graph_cache_access(cache_key)
                
                # 从JSON数据重构图对象
                graph_dict = cached.graph_data
                if isinstance(graph_dict, str):
                    graph_dict = json.loads(graph_dict)
                
                # 这里需要实现从字典重构MultiLayerGraph的逻辑
                # 简化实现：直接返回None，强制重新构建
                return None
            
        except Exception as e:
            print(f"获取缓存图数据失败: {str(e)}")
        
        return None
    
    def _cache_graph(self, cache_key: str, graph: MultiLayerGraph, analysis_type: str):
        """缓存图数据"""
        try:
            # 清理过期缓存
            self._cleanup_expired_cache()
            
            # 序列化图数据
            graph_dict = graph.to_dict()
            
            # 创建缓存记录
            cache_record = MultiLayerGraphCache(
                cache_key=cache_key,
                target_contract=graph.target_contract,
                start_block=graph.time_range[0],
                end_block=graph.time_range[1],
                graph_data=graph_dict,
                related_addresses=list(graph.global_stats.get("unique_addresses", [])),
                analysis_type=analysis_type,
                node_count=graph.global_stats.get("total_nodes", 0),
                layer_count=len(graph.layers),
                expires_at=datetime.utcnow() + timedelta(hours=self.cache_expire_hours)
            )
            
            self.db.add(cache_record)
            self.db.commit()
            print(f"缓存图数据: {cache_key}")
            
        except Exception as e:
            print(f"缓存图数据失败: {str(e)}")
            self.db.rollback()
    
    def _cleanup_expired_cache(self):
        """清理过期的缓存条目"""
        try:
            current_time = datetime.now()
            expired_cache = self.db.query(MultiLayerGraphCache).filter(
                MultiLayerGraphCache.expires_at < current_time
            ).all()
            
            for cache_entry in expired_cache:
                self.db.delete(cache_entry)
            
            if expired_cache:
                self.db.commit()
                print(f"清理了 {len(expired_cache)} 个过期缓存条目")
                
        except Exception as e:
            self.db.rollback()
            print(f"清理过期缓存时出错: {str(e)}")

    def _cache_analysis_result(self, cache_key: str, analysis_data: Dict, analysis_type: str):
        """缓存分析结果（用于enhanced_workflow集成）"""
        try:
            # 检查是否已存在相同的缓存
            existing_cache = self.db.query(MultiLayerGraphCache).filter(
                MultiLayerGraphCache.cache_key == cache_key
            ).first()
            
            if existing_cache:
                # 更新现有缓存
                existing_cache.graph_data = analysis_data
                existing_cache.last_accessed = datetime.now()
                existing_cache.access_count += 1
                existing_cache.expires_at = datetime.now() + timedelta(hours=24)
            else:
                # 创建新的缓存条目
                cache_entry = MultiLayerGraphCache(
                    cache_key=cache_key,
                    target_contract=analysis_data.get('target_contract', ''),
                    start_block=0,  # 分析结果缓存不需要具体区块
                    end_block=0,
                    graph_data=analysis_data,
                    analysis_type=analysis_type,
                    node_count=0,
                    layer_count=0,
                    expires_at=datetime.now() + timedelta(hours=24),
                    access_count=1
                )
                self.db.add(cache_entry)
            
            self.db.commit()
            print(f"分析结果已缓存: {cache_key}")
            
        except Exception as e:
            self.db.rollback()
            print(f"缓存分析结果时出错: {str(e)}")

    def get_all_addresses_from_graph(self, graph: MultiLayerGraph) -> Set[str]:
        """从多层图中提取所有地址"""
        addresses = set()
        
        try:
            for layer in graph.layers:
                if layer.node_type == NodeType.ADDRESS:
                    for node in layer.nodes.values():
                        if hasattr(node, 'address'):
                            addresses.add(node.address.lower())
                elif hasattr(layer, 'nodes'):
                    for node in layer.nodes.values():
                        # 从其他类型的节点中提取地址信息
                        if hasattr(node, 'from_address') and node.from_address:
                            addresses.add(node.from_address.lower())
                        if hasattr(node, 'to_address') and node.to_address:
                            addresses.add(node.to_address.lower())
                        if hasattr(node, 'contract_address') and node.contract_address:
                            addresses.add(node.contract_address.lower())
        
        except Exception as e:
            print(f"从多层图提取地址时出错: {str(e)}")
        
        return addresses

    def enhance_graph_with_risk_scores(self, graph: MultiLayerGraph) -> MultiLayerGraph:
        """为图中的地址节点添加风险评分"""
        try:
            address_layer = None
            for layer in graph.layers:
                if layer.node_type == NodeType.ADDRESS:
                    address_layer = layer
                    break
            
            if not address_layer:
                return graph
            
            for node in address_layer.nodes.values():
                if hasattr(node, 'address'):
                    risk_score = self.get_contract_risk_score(node.address)
                    
                    # 将风险评分添加到节点属性中
                    if hasattr(node, 'metadata'):
                        node.metadata['risk_score'] = risk_score
                    else:
                        node.metadata = {'risk_score': risk_score}
            
            print("已为图中的地址节点添加风险评分")
            
        except Exception as e:
            print(f"添加风险评分时出错: {str(e)}")
        
        return graph

    def get_enhanced_prompt_with_context(
        self,
        target_contract: str,
        start_block: int,
        end_block: int,
        analysis_type: str = "security",
        user_query: str = ""
    ) -> str:
        """生成包含索引上下文的增强提示词"""
        
        prompt_parts = []
        
        # 基础查询信息
        prompt_parts.append(f"""
**分析目标:**
- 合约地址: {target_contract}
- 区块范围: {start_block} - {end_block}
- 分析类型: {analysis_type}
- 用户查询: {user_query}
""")
        
        # 从索引获取合约基础信息
        try:
            source_info = self.data_access.get_contract_source_by_address(target_contract)
            if source_info:
                prompt_parts.append(f"""
**合约基础信息:**
- 合约名称: {source_info.contract_name or 'Unknown'}
- 编译器版本: {source_info.compiler_version or 'Unknown'}
- 验证状态: {source_info.verification_status}
""")
            
            creator_info = self.data_access.get_contract_creator(target_contract)
            if creator_info:
                prompt_parts.append(f"""
**创建信息:**
- 创建者: {creator_info.creator_address}
- 创建区块: {creator_info.creation_block_number}
- 创建交易: {creator_info.creation_tx_hash}
""")
            
            labels = self.data_access.get_address_labels(target_contract)
            if labels:
                label_info = ", ".join([f"{l.label_type}:{l.label_name}" for l in labels])
                prompt_parts.append(f"""
**地址标签:**
- 标签: {label_info}
""")
                
        except Exception as e:
            print(f"获取索引信息时出错: {str(e)}")
        
        # 多层图数据
        try:
            graph_data = self.get_optimized_graph_for_llm(
                target_contract, start_block, end_block, analysis_type
            )
            prompt_parts.append(f"""
**多层图分析数据:**
{graph_data}
""")
        except Exception as e:
            print(f"获取图数据时出错: {str(e)}")
        
        return "\n".join(prompt_parts)

    def get_comprehensive_security_context(
        self,
        target_contract: str,
        related_addresses: List[str] = None
    ) -> Dict[str, Any]:
        """获取全面的安全上下文信息"""
        
        context = {
            'target_contract': target_contract,
            'risk_indicators': [],
            'trust_indicators': [],
            'related_risks': []
        }
        
        try:
            # 分析目标合约
            target_risk = self.get_contract_risk_score(target_contract)
            context['target_risk_score'] = target_risk
            
            if target_risk['total_score'] > 70:
                context['risk_indicators'].append(f"目标合约风险评分高: {target_risk['total_score']}")
            
            # 分析相关地址
            if related_addresses:
                high_risk_addresses = []
                
                for addr in related_addresses[:10]:  # 限制分析数量
                    addr_risk = self.get_contract_risk_score(addr)
                    if addr_risk['total_score'] > 60:
                        high_risk_addresses.append((addr, addr_risk['total_score']))
                
                if high_risk_addresses:
                    context['related_risks'] = high_risk_addresses
                    context['risk_indicators'].append(
                        f"发现 {len(high_risk_addresses)} 个高风险相关地址"
                    )
            
            # 检查地址标签
            labels = self.data_access.get_address_labels(target_contract)
            verified_labels = [l for l in labels if l.verified]
            
            if verified_labels:
                context['trust_indicators'].append(
                    f"具有 {len(verified_labels)} 个已验证标签"
                )
            
            # 检查源码验证状态
            source_info = self.data_access.get_contract_source_by_address(target_contract)
            if source_info and source_info.verification_status == 'verified':
                context['trust_indicators'].append("合约源码已验证")
            else:
                context['risk_indicators'].append("合约源码未验证")
                
        except Exception as e:
            print(f"获取安全上下文时出错: {str(e)}")
            context['error'] = str(e)
        
        return context
    
    def get_optimized_graph_for_llm(
        self,
        target_contract: str,
        start_block: int,
        end_block: int,
        analysis_type: str = "security",
        max_nodes_per_layer: int = 30,
        format_type: str = "focused"
    ) -> str:
        """获取为LLM优化的图数据"""
        
        # 构建增强的多层图
        graph = self.build_enhanced_multilayer_graph(
            target_contract=target_contract,
            start_block=start_block,
            end_block=end_block,
            analysis_type=analysis_type
        )
        
        # 根据格式类型进行序列化
        if format_type == "focused":
            return self._create_focused_llm_format(graph, max_nodes_per_layer)
        elif format_type == "compact":
            return self.graph_serializer.to_compact_format(graph, max_nodes_per_layer * 4)
        else:
            return self.graph_serializer.to_llm_format(graph, max_nodes_per_layer)
    
    def _create_focused_llm_format(self, graph: MultiLayerGraph, max_nodes: int) -> str:
        """创建聚焦的LLM格式，突出安全相关信息"""
        output_lines = [
            "# 增强以太坊多层交易图分析",
            f"目标合约: {graph.target_contract}",
            f"分析时间范围: 区块 {graph.time_range[0]} - {graph.time_range[1]}",
            f"",
            "## 关键发现摘要"
        ]
        
        # 统计信息
        stats = graph.global_stats
        output_lines.extend([
            f"- 总节点数: {stats.get('total_nodes', 0)}",
            f"- 总交易数: {stats.get('total_transactions', 0)}",
            f"- 涉及合约数: {stats.get('total_contracts', 0)}",
            f"- 总转账金额: {stats.get('total_value_transferred', '0')} Wei",
            f"- 唯一地址数: {len(stats.get('unique_addresses', []))}",
            ""
        ])
        
        # 处理每一层
        for layer_id in sorted(graph.layers.keys()):
            layer = graph.layers[layer_id]
            output_lines.append(f"## {layer.layer_name} ({layer.get_node_count()} 节点)")
            
            # 根据重要性排序节点
            important_nodes = self._get_important_nodes_with_index_info(
                layer, max_nodes // len(graph.layers)
            )
            
            for node in important_nodes:
                node_desc = self._format_node_with_index_info(node)
                output_lines.append(f"- {node_desc}")
            
            output_lines.append("")
        
        # 安全关注点
        security_findings = self._extract_security_findings(graph)
        if security_findings:
            output_lines.extend([
                "## 安全关注点",
                *[f"- {finding}" for finding in security_findings],
                ""
            ])
        
        return "\n".join(output_lines)
    
    def _get_important_nodes_with_index_info(self, layer, max_nodes: int) -> List:
        """获取包含索引信息的重要节点"""
        nodes = list(layer.nodes.values())
        
        # 根据不同类型的节点进行重要性排序
        if layer.layer_name == "地址层":
            # 优先显示有标签、已验证或有代币信息的地址
            nodes.sort(key=lambda n: (
                bool(n.properties.get("labels")),
                bool(n.properties.get("is_verified")),
                bool(n.properties.get("token_symbol")),
                int(n.properties.get("in_degree", 0)) + int(n.properties.get("out_degree", 0))
            ), reverse=True)
        elif layer.layer_name == "函数调用层":
            # 优先显示有使用统计的函数
            nodes.sort(key=lambda n: (
                int(n.properties.get("usage_count", 0)),
                bool(n.properties.get("function_signature"))
            ), reverse=True)
        
        return nodes[:max_nodes]
    
    def _format_node_with_index_info(self, node) -> str:
        """格式化包含索引信息的节点"""
        props = node.properties
        
        if node.node_type.value == "address":
            desc_parts = [f"地址 {props.get('address', 'unknown')}"]
            
            if props.get("contract_name"):
                desc_parts.append(f"名称: {props['contract_name']}")
            
            if props.get("token_symbol"):
                desc_parts.append(f"代币: {props['token_symbol']}")
            
            if props.get("labels"):
                labels = [label["name"] for label in props["labels"][:2]]
                desc_parts.append(f"标签: {', '.join(labels)}")
            
            if props.get("verification_status"):
                desc_parts.append(f"验证状态: {props['verification_status']}")
            
            in_degree = props.get("in_degree", 0)
            out_degree = props.get("out_degree", 0)
            desc_parts.append(f"交易: 入{in_degree}/出{out_degree}")
            
        elif node.node_type.value == "function_call":
            desc_parts = [f"函数调用 {props.get('function_name', 'unknown')}"]
            
            if props.get("function_signature"):
                desc_parts.append(f"签名: {props['function_signature']}")
            
            if props.get("usage_count"):
                desc_parts.append(f"使用次数: {props['usage_count']}")
            
            if props.get("call_depth"):
                desc_parts.append(f"调用深度: {props['call_depth']}")
        
        else:
            # 其他类型节点的格式化
            desc_parts = [f"{node.node_type.value} {node.node_id}"]
        
        return " | ".join(desc_parts)
    
    def _extract_security_findings(self, graph: MultiLayerGraph) -> List[str]:
        """提取安全相关发现"""
        findings = []
        
        # 检查未验证合约
        address_layer = graph.get_layer(1)
        if address_layer:
            unverified_contracts = [
                node for node in address_layer.nodes.values()
                if (node.properties.get("address_type") == "Contract" and 
                    node.properties.get("verification_status") == "unverified")
            ]
            if unverified_contracts:
                findings.append(f"发现 {len(unverified_contracts)} 个未验证合约")
        
        # 检查高风险标签
        high_risk_labels = ["mixer", "gambling", "phishing", "scam"]
        for layer in graph.layers.values():
            for node in layer.nodes.values():
                labels = node.properties.get("labels", [])
                for label in labels:
                    if label.get("type") in high_risk_labels:
                        findings.append(f"发现高风险地址标签: {label.get('name')}")
        
        # 检查代理合约
        proxy_contracts = [
            node for node in address_layer.nodes.values()
            if node.properties.get("proxy_info")
        ] if address_layer else []
        if proxy_contracts:
            findings.append(f"发现 {len(proxy_contracts)} 个代理合约")
        
        return findings[:10]  # 限制发现数量
    
    def get_contract_risk_score(self, contract_address: str) -> Dict[str, Any]:
        """计算合约的风险评分"""
        risk_score = 0.0
        risk_factors = []
        
        # 获取合约基本信息
        source_info = self.data_access.get_contract_source_by_address(contract_address)
        creator_info = self.data_access.get_contract_creator(contract_address)
        labels = self.data_access.get_address_labels(contract_address)
        
        # 验证状态风险
        if not source_info or source_info.verification_status != "verified":
            risk_score += 30
            risk_factors.append("合约未验证")
        
        # 标签风险
        high_risk_labels = ["mixer", "gambling", "phishing", "scam", "suspicious"]
        for label in labels:
            if label.label_type in high_risk_labels:
                risk_score += 40
                risk_factors.append(f"高风险标签: {label.label_name}")
        
        # 创建者风险
        if creator_info:
            creator_contracts = self.data_access.get_contracts_by_creator(creator_info.creator_address)
            if len(creator_contracts) > 10:
                risk_score += 10
                risk_factors.append("创建者创建了大量合约")
        
        # 计算最终风险等级
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "contract_address": contract_address,
            "risk_score": min(risk_score, 100),  # 限制在100以内
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "verification_status": source_info.verification_status if source_info else "unknown",
            "label_count": len(labels),
            "creator_address": creator_info.creator_address if creator_info else None
        }
    
    def batch_update_indexes(self, interactions: List[Dict], batch_size: int = 1000):
        """批量更新索引信息"""
        print(f"批量更新索引，共 {len(interactions)} 条交互记录")
        
        function_signatures = {}
        event_signatures = {}
        
        for i, interaction in enumerate(interactions):
            # 提取函数签名
            if interaction.get("input_data") and len(interaction["input_data"]) >= 10:
                selector = interaction["input_data"][:10]
                if selector not in function_signatures:
                    function_signatures[selector] = {
                        "function_selector": selector,
                        "function_signature": f"{interaction.get('method_name', 'unknown')}()",
                        "function_name": interaction.get('method_name', 'unknown'),
                        "source_contract": interaction.get('target_contract'),
                        "usage_count": 1,
                        "first_seen_block": interaction.get('block_number'),
                        "last_seen_block": interaction.get('block_number')
                    }
                else:
                    function_signatures[selector]["usage_count"] += 1
                    function_signatures[selector]["last_seen_block"] = max(
                        function_signatures[selector]["last_seen_block"],
                        interaction.get('block_number', 0)
                    )
            
            # 批量提交
            if (i + 1) % batch_size == 0:
                self._commit_batch_updates(function_signatures, event_signatures)
                function_signatures.clear()
                event_signatures.clear()
                print(f"已处理 {i + 1} 条记录")
        
        # 提交剩余的更新
        if function_signatures or event_signatures:
            self._commit_batch_updates(function_signatures, event_signatures)
        
        print("批量索引更新完成")
    
    def _commit_batch_updates(self, function_sigs: Dict, event_sigs: Dict):
        """提交批量更新"""
        try:
            # 更新函数签名
            if function_sigs:
                self.data_access.batch_upsert_function_signatures(list(function_sigs.values()))
            
            # 更新事件签名
            if event_sigs:
                self.data_access.batch_upsert_event_signatures(list(event_sigs.values()))
                
        except Exception as e:
            print(f"批量更新失败: {str(e)}")
            self.db.rollback()

# 便捷函数
def create_enhanced_graph_analysis(
    db_session: Session,
    target_contract: str,
    start_block: int,
    end_block: int,
    analysis_type: str = "security"
) -> str:
    """创建增强的图分析（便捷函数）"""
    integrator = GraphDatabaseIntegrator(db_session)
    return integrator.get_optimized_graph_for_llm(
        target_contract=target_contract,
        start_block=start_block,
        end_block=end_block,
        analysis_type=analysis_type,
        format_type="focused"
    )

def get_contract_comprehensive_info(
    db_session: Session,
    contract_address: str
) -> Dict[str, Any]:
    """获取合约的综合信息（便捷函数）"""
    integrator = GraphDatabaseIntegrator(db_session)
    data_access = IndexedDataAccess(db_session)
    
    return {
        "source_info": data_access.get_contract_source_by_address(contract_address),
        "creator_info": data_access.get_contract_creator(contract_address),
        "labels": data_access.get_address_labels(contract_address),
        "token_info": data_access.get_token_info(contract_address),
        "risk_assessment": integrator.get_contract_risk_score(contract_address)
    } 