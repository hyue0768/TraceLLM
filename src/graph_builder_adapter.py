"""
GraphBuilderAdapter - 交易图构建适配层
负责抽象交易图构建接口，为后续切换到增强实现做准备
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import json
import traceback
from datetime import datetime


class GraphBuilderInterface(ABC):
    """交易图构建器抽象接口"""
    
    @abstractmethod
    def build_call_graph(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int, 
        max_depth: int = 3,
        pruning_enabled: bool = True,
        related_addresses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """构建交易调用图"""
        pass
        
    @abstractmethod
    def get_supported_features(self) -> List[str]:
        """获取支持的功能特性"""
        pass
        
    @abstractmethod
    def validate_parameters(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int
    ) -> bool:
        """验证输入参数有效性"""
        pass

    @abstractmethod
    def get_builder_info(self) -> Dict[str, Any]:
        """获取构建器信息"""
        pass


class LegacyGraphBuilder(GraphBuilderInterface):
    """原有交易图构建器的适配器实现"""
    
    def __init__(self):
        self.name = "LegacyGraphBuilder"
        self.version = "1.0.0"
        self._load_legacy_function()
    
    def _load_legacy_function(self):
        """加载原有的build_transaction_call_graph函数"""
        try:
            from analyze_user_behavior import build_transaction_call_graph
            self._legacy_function = build_transaction_call_graph
            self._is_available = True
            print(f"✅ {self.name}: 成功加载原有交易图构建函数")
        except ImportError as e:
            print(f"❌ {self.name}: 无法导入原有函数 - {str(e)}")
            self._legacy_function = None
            self._is_available = False
    
    def build_call_graph(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int, 
        max_depth: int = 3,
        pruning_enabled: bool = True,
        related_addresses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """使用原有函数构建调用图"""
        if not self._is_available:
            raise RuntimeError(f"{self.name}: 原有函数不可用")
        
        if not self.validate_parameters(target_contract, start_block, end_block):
            raise ValueError("输入参数验证失败")
        
        print(f"🔧 {self.name}: 使用原有实现构建调用图")
        
        try:
            result = self._legacy_function(
                target_contract=target_contract,
                start_block=start_block,
                end_block=end_block,
                max_depth=max_depth,
                pruning_enabled=pruning_enabled,
                related_addresses=related_addresses
            )
            
            validated_result = self._validate_output(result)
            print(f"✅ {self.name}: 成功构建调用图，交易数量: {len(validated_result)}")
            return validated_result
            
        except Exception as e:
            print(f"❌ {self.name}: 构建调用图失败 - {str(e)}")
            traceback.print_exc()
            return {}
    
    def _validate_output(self, result: Any) -> Dict[str, Any]:
        """验证输出结果结构"""
        if not isinstance(result, dict):
            return {}
        
        validated = {}
        for tx_hash, data in result.items():
            if isinstance(data, dict) and 'call_hierarchy' in data and 'related_contracts' in data:
                if isinstance(data['related_contracts'], set):
                    validated[tx_hash] = data
                elif isinstance(data['related_contracts'], list):
                    validated[tx_hash] = {
                        'call_hierarchy': data['call_hierarchy'],
                        'related_contracts': set(data['related_contracts'])
                    }
                else:
                    validated[tx_hash] = {
                        'call_hierarchy': data.get('call_hierarchy', {}),
                        'related_contracts': set()
                    }
            else:
                validated[tx_hash] = {
                    'call_hierarchy': {},
                    'related_contracts': set()
                }
        
        return validated
    
    def get_supported_features(self) -> List[str]:
        """获取支持的功能特性"""
        return [
            "transaction_tracing",
            "call_hierarchy_analysis", 
            "contract_relationship_extraction",
            "depth_limited_traversal",
            "pruning_optimization",
            "related_address_support"
        ]
    
    def validate_parameters(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int
    ) -> bool:
        """验证输入参数"""
        try:
            from web3 import Web3
            
            if not target_contract or not Web3.is_address(target_contract):
                print(f"❌ {self.name}: 无效的合约地址 - {target_contract}")
                return False
            
            if not isinstance(start_block, int) or not isinstance(end_block, int):
                print(f"❌ {self.name}: 区块编号必须是整数")
                return False
            
            if start_block < 0 or end_block < 0:
                print(f"❌ {self.name}: 区块编号不能为负数")
                return False
            
            if start_block > end_block:
                print(f"❌ {self.name}: 起始区块不能大于结束区块")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ {self.name}: 参数验证失败 - {str(e)}")
            return False

    def get_builder_info(self) -> Dict[str, Any]:
        """获取构建器信息"""
        return {
            "name": self.name,
            "version": self.version,
            "available": self._is_available,
            "features": self.get_supported_features()
        }


class EnhancedGraphBuilder(GraphBuilderInterface):
    """增强版实现的适配器"""
    
    def __init__(self):
        self.name = "EnhancedGraphBuilder"
        self.version = "2.0.0"
        self._is_available = False
        self._enhanced_builder = None
        self._load_enhanced_builder()
    
    def _load_enhanced_builder(self):
        """加载增强版的交易图构建器"""
        try:
            from enhanced_workflow import TransactionGraphBuilder
            from database import get_db
            
            # 创建增强版构建器实例
            db_session = next(get_db())
            self._enhanced_builder = TransactionGraphBuilder(db_session)
            self._is_available = True
            print("✅ EnhancedGraphBuilder: 成功加载增强版交易图构建器")
        except Exception as e:
            self._is_available = False
            print(f"❌ EnhancedGraphBuilder: 增强版构建器初始化失败: {str(e)}")
    
    def get_supported_features(self) -> List[str]:
        """获取支持的功能特性"""
        return [
            "transaction_tracing",
            "call_hierarchy_analysis",
            "contract_relationship_extraction",
            "depth_limited_traversal",
            "pruning_optimization",
            "related_address_support",
            "multilayer_caching",
            "metadata_enhancement",
            "node_information_enrichment",
            "performance_optimization",
            "llm_node_analysis",
            "security_pattern_detection",
            "custom_analysis_types"
        ]
    
    def validate_parameters(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int
    ) -> bool:
        """验证输入参数"""
        if not self._is_available or not self._enhanced_builder:
            print("❌ EnhancedGraphBuilder: 构建器不可用")
            return False
        
        try:
            return self._enhanced_builder._validate_inputs(target_contract, start_block, end_block)
        except Exception as e:
            print(f"❌ EnhancedGraphBuilder: 参数验证失败 - {str(e)}")
            return False
    
    def build_call_graph(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int, 
        max_depth: int = 3,
        pruning_enabled: bool = True,
        related_addresses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """构建交易调用图"""
        if not self._is_available or not self._enhanced_builder:
            raise RuntimeError("EnhancedGraphBuilder不可用")
        
        print("🚀 EnhancedGraphBuilder: 使用增强版实现构建调用图")
        
        try:
            # 调用增强版构建器
            result = self._enhanced_builder.build_transaction_graph(
                target_contract=target_contract,
                start_block=start_block,
                end_block=end_block,
                analysis_type="security",
                max_depth=max_depth,
                use_cache=True,
                force_rebuild=False
            )
            
            # 将增强版格式转换为兼容格式
            compatible_result = self._convert_to_legacy_format(result)
            
            print(f"✅ EnhancedGraphBuilder: 成功构建调用图")
            return compatible_result
            
        except Exception as e:
            error_msg = f"EnhancedGraphBuilder构建失败: {str(e)}"
            print(f"❌ {error_msg}")
            raise Exception(error_msg)
    
    def _convert_to_legacy_format(self, enhanced_result: Dict[str, Any]) -> Dict[str, Any]:
        """将增强版格式转换为兼容原有格式"""
        try:
            # 从增强版结果中提取图数据
            graph_data = enhanced_result.get('graph_data', {})
            
            # 如果图数据为空，返回空字典
            if not graph_data:
                print("⚠️ EnhancedGraphBuilder: 图数据为空")
                return {}
            
            # 🔧 修复：正确处理增强版的图数据结构
            legacy_format = {}
            
            # 检查图数据的结构
            if isinstance(graph_data, dict):
                # 情况1：图数据直接包含call_graph字段
                if 'call_graph' in graph_data:
                    call_graph = graph_data['call_graph']
                    print(f"📊 EnhancedGraphBuilder: 从call_graph字段提取数据，交易数: {len(call_graph) if isinstance(call_graph, dict) else 0}")
                    
                    if isinstance(call_graph, dict):
                        for tx_hash, tx_data in call_graph.items():
                            if isinstance(tx_data, dict):
                                legacy_format[tx_hash] = {
                                    'call_hierarchy': tx_data.get('call_hierarchy', {}),
                                    'related_contracts': set(tx_data.get('related_contracts', []))
                                }
                
                # 情况2：图数据本身就是交易哈希的字典
                else:
                    print(f"📊 EnhancedGraphBuilder: 直接处理图数据字典，交易数: {len(graph_data)}")
                    
                    for tx_hash, tx_data in graph_data.items():
                        if isinstance(tx_data, dict):
                            # 检查是否有必要的字段
                            if 'call_hierarchy' in tx_data or 'related_contracts' in tx_data:
                                legacy_format[tx_hash] = {
                                    'call_hierarchy': tx_data.get('call_hierarchy', {}),
                                    'related_contracts': set(tx_data.get('related_contracts', []))
                                }
                            else:
                                # 如果没有标准字段，尝试构建基础结构
                                legacy_format[tx_hash] = {
                                    'call_hierarchy': {
                                        'from': tx_data.get('from', ''),
                                        'to': tx_data.get('to', ''),
                                        'method': tx_data.get('method_name', ''),
                                        'children': []
                                    },
                                    'related_contracts': set(tx_data.get('related_contracts', []))
                                }
            
            # 验证转换结果
            if not legacy_format:
                print("⚠️ EnhancedGraphBuilder: 转换后的格式为空，可能是数据结构不匹配")
                print(f"原始数据结构: {type(graph_data)}")
                if isinstance(graph_data, dict):
                    print(f"原始数据键: {list(graph_data.keys())[:5]}...")  # 只显示前5个键
            
            print(f"✅ EnhancedGraphBuilder: 转换为兼容格式，交易数: {len(legacy_format)}")
            return legacy_format
            
        except Exception as e:
            print(f"⚠️ EnhancedGraphBuilder: 格式转换失败: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # 返回原始数据或空字典
            original_data = enhanced_result.get('graph_data', {})
            if isinstance(original_data, dict):
                return original_data
            else:
                return {}
    
    def get_builder_info(self) -> Dict[str, Any]:
        """获取构建器信息"""
        return {
            "name": self.name,
            "version": self.version,
            "available": self._is_available,
            "features": self.get_supported_features()
        }


class GraphBuilderAdapter:
    """交易图构建适配器"""
    
    def __init__(self, preferred_builder: str = "auto"):
        """
        初始化适配器
        
        Args:
            preferred_builder: 偏好的构建器类型 ("legacy", "enhanced", "auto")
        """
        self.preferred_builder = preferred_builder
        self.builders = {}
        self.current_builder = None
        self.build_history = []
        
        print("🔧 GraphBuilderAdapter: 初始化构建器...")
        self._initialize_builders()
    
    def _initialize_builders(self):
        """初始化所有可用的构建器"""
        # 初始化 Legacy 构建器
        try:
            self.builders["legacy"] = LegacyGraphBuilder()
        except Exception as e:
            print(f"❌ Legacy构建器初始化失败: {str(e)}")
        
        # 初始化增强版构建器
        try:
            self.builders["enhanced"] = EnhancedGraphBuilder()
        except Exception as e:
            print(f"❌ Enhanced构建器初始化失败: {str(e)}")
        
        # 选择当前构建器
        self._select_builder()
    
    def _select_builder(self):
        """选择当前使用的构建器"""
        if self.preferred_builder == "legacy" and "legacy" in self.builders:
            if self.builders["legacy"]._is_available:
                self.current_builder = self.builders["legacy"]
                print("🔧 选择: 使用原有构建器")
                return
            else:
                print("❌ 原有构建器不可用")
        
        elif self.preferred_builder == "enhanced" and "enhanced" in self.builders:
            if self.builders["enhanced"]._is_available:
                self.current_builder = self.builders["enhanced"]
                print("🚀 选择: 使用增强版构建器")
                return
            else:
                print("❌ 增强版构建器不可用")
        
        elif self.preferred_builder == "auto":
            # 自动选择：优先使用增强版，回退到原有版本
            if "enhanced" in self.builders and self.builders["enhanced"]._is_available:
                self.current_builder = self.builders["enhanced"]
                print("🚀 自动选择: 使用增强版构建器")
                return
            elif "legacy" in self.builders and self.builders["legacy"]._is_available:
                self.current_builder = self.builders["legacy"]
                print("🔧 自动选择: 回退到原有构建器")
                return
        
        # 如果没有可用的构建器
        if "legacy" in self.builders and self.builders["legacy"]._is_available:
            self.current_builder = self.builders["legacy"]
            print("✅ 原有构建器加载成功")
        else:
            raise RuntimeError("原有构建器不可用")
    
    def build_transaction_call_graph(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int, 
        max_depth: int = 3,
        pruning_enabled: bool = True,
        related_addresses: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """构建交易调用图"""
        if not self.current_builder:
            raise RuntimeError("没有可用的构建器")
        
        start_time = datetime.now()
        builder_info = self.current_builder.get_builder_info()
        
        print(f"\n🔍 开始构建交易调用图...")
        print(f"   构建器: {builder_info['name']} v{builder_info['version']}")
        
        try:
            # 验证参数
            if not self.current_builder.validate_parameters(target_contract, start_block, end_block):
                raise ValueError("参数验证失败")
            
            # 构建调用图
            result = self.current_builder.build_call_graph(
                target_contract, start_block, end_block, max_depth, pruning_enabled, related_addresses
            )
            
            # 记录构建历史
            build_time = (datetime.now() - start_time).total_seconds()
            self._record_build(builder_info['name'], build_time, len(result))
            
            print(f"✅ 调用图构建完成，耗时: {build_time:.2f} 秒，交易数: {len(result)}")
            return result
            
        except Exception as e:
            build_time = (datetime.now() - start_time).total_seconds()
            self._record_build(builder_info['name'], build_time, 0, str(e))
            
            print(f"❌ 调用图构建失败: {str(e)}")
            # 返回空字典而不是抛出异常，确保系统稳定性
            return {}
    
    def get_builder_info(self) -> Dict[str, Any]:
        """获取当前构建器信息"""
        if not self.current_builder:
            return {"error": "没有可用的构建器"}
        
        info = self.current_builder.get_builder_info()
        info["adapter_version"] = "1.0.0"
        info["preferred_builder"] = self.preferred_builder
        return info
    
    def get_available_builders(self) -> Dict[str, Dict[str, Any]]:
        """获取所有可用构建器的信息"""
        available = {}
        for name, builder in self.builders.items():
            available[name] = builder.get_builder_info()
        return available
    
    def switch_builder(self, builder_type: str) -> bool:
        """切换构建器类型"""
        if builder_type not in self.builders:
            print(f"❌ 未知的构建器类型: {builder_type}")
            return False
        
        if not self.builders[builder_type]._is_available:
            print(f"❌ 构建器 {builder_type} 不可用")
            return False
        
        self.current_builder = self.builders[builder_type]
        self.preferred_builder = builder_type
        print(f"✅ 已切换到构建器: {builder_type}")
        return True
    
    def compare_builders(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int, 
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """A/B测试：对比不同构建器的结果"""
        print(f"\n🔬 开始A/B测试对比...")
        print(f"   目标合约: {target_contract}")
        print(f"   区块范围: {start_block} - {end_block}")
        
        comparison_results = {
            "test_parameters": {
                "target_contract": target_contract,
                "start_block": start_block,
                "end_block": end_block,
                "max_depth": max_depth
            },
            "results": {},
            "comparison": {}
        }
        
        # 保存原始构建器选择
        original_builder = self.preferred_builder
        
        # 测试所有可用的构建器
        for builder_name, builder in self.builders.items():
            if not builder._is_available:
                print(f"⏭️ 跳过不可用的构建器: {builder_name}")
                continue
            
            print(f"\n📊 测试构建器: {builder_name}")
            
            try:
                # 切换到当前测试的构建器
                self.current_builder = builder
                
                # 记录开始时间
                start_time = datetime.now()
                
                # 构建交易图
                result = builder.build_call_graph(
                    target_contract, start_block, end_block, max_depth, True, None
                )
                
                # 计算耗时
                build_time = (datetime.now() - start_time).total_seconds()
                
                # 分析结果结构
                graph_stats = self._analyze_graph_structure(result)
                
                comparison_results["results"][builder_name] = {
                    "success": True,
                    "build_time": build_time,
                    "transaction_count": len(result),
                    "graph_statistics": graph_stats,
                    "builder_info": builder.get_builder_info()
                }
                
                print(f"✅ {builder_name} 完成: {len(result)} 交易, 耗时 {build_time:.2f}s")
                
            except Exception as e:
                comparison_results["results"][builder_name] = {
                    "success": False,
                    "error": str(e),
                    "builder_info": builder.get_builder_info()
                }
                print(f"❌ {builder_name} 失败: {str(e)}")
        
        # 生成对比分析
        comparison_results["comparison"] = self._generate_comparison_analysis(comparison_results["results"])
        
        # 恢复原始构建器
        self.preferred_builder = original_builder
        self._select_builder()
        
        print(f"\n🎯 A/B测试完成")
        return comparison_results
    
    def _analyze_graph_structure(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析图的结构特征"""
        if not graph_data:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "max_depth": 0,
                "contract_count": 0,
                "data_hash": "empty"
            }
        
        total_nodes = 0
        total_edges = 0
        max_depth = 0
        contracts = set()
        
        for tx_hash, tx_data in graph_data.items():
            if isinstance(tx_data, dict):
                # 计算节点和边
                hierarchy = tx_data.get('call_hierarchy', {})
                nodes, edges = self._count_hierarchy_nodes_edges(hierarchy)
                total_nodes += nodes
                total_edges += edges
                
                # 计算最大深度
                depth = self._calculate_hierarchy_depth(hierarchy)
                max_depth = max(max_depth, depth)
                
                # 收集合约地址
                related_contracts = tx_data.get('related_contracts', set())
                if isinstance(related_contracts, (list, set)):
                    contracts.update(related_contracts)
        
        # 生成数据哈希用于对比
        data_str = json.dumps(graph_data, sort_keys=True, default=str)
        import hashlib
        data_hash = hashlib.md5(data_str.encode()).hexdigest()[:8]
        
        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "max_depth": max_depth,
            "contract_count": len(contracts),
            "transaction_count": len(graph_data),
            "data_hash": data_hash
        }
    
    def _count_hierarchy_nodes_edges(self, hierarchy: Dict[str, Any]) -> tuple:
        """计算层次结构中的节点和边数量"""
        if not hierarchy:
            return 0, 0
        
        nodes = 1  # 当前节点
        edges = 0
        
        children = hierarchy.get('children', [])
        for child in children:
            edges += 1  # 到子节点的边
            child_nodes, child_edges = self._count_hierarchy_nodes_edges(child)
            nodes += child_nodes
            edges += child_edges
        
        return nodes, edges
    
    def _calculate_hierarchy_depth(self, hierarchy: Dict[str, Any]) -> int:
        """计算层次结构的最大深度"""
        if not hierarchy:
            return 0
        
        children = hierarchy.get('children', [])
        if not children:
            return 1
        
        max_child_depth = 0
        for child in children:
            child_depth = self._calculate_hierarchy_depth(child)
            max_child_depth = max(max_child_depth, child_depth)
        
        return 1 + max_child_depth
    
    def _generate_comparison_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成对比分析结果"""
        successful_results = {k: v for k, v in results.items() if v.get('success', False)}
        
        if len(successful_results) < 2:
            return {"status": "insufficient_data", "message": "需要至少2个成功的结果进行对比"}
        
        # 性能对比
        performance_comparison = {}
        for name, result in successful_results.items():
            performance_comparison[name] = {
                "build_time": result["build_time"],
                "transaction_count": result["transaction_count"],
                "efficiency": result["transaction_count"] / max(result["build_time"], 0.001)
            }
        
        # 找出最快和最慢的
        fastest = min(successful_results.items(), key=lambda x: x[1]["build_time"])
        slowest = max(successful_results.items(), key=lambda x: x[1]["build_time"])
        
        # 数据一致性检查
        hashes = [result["graph_statistics"]["data_hash"] for result in successful_results.values()]
        data_consistent = len(set(hashes)) == 1
        
        return {
            "status": "success",
            "performance_comparison": performance_comparison,
            "fastest_builder": {"name": fastest[0], "time": fastest[1]["build_time"]},
            "slowest_builder": {"name": slowest[0], "time": slowest[1]["build_time"]},
            "data_consistency": {
                "consistent": data_consistent,
                "unique_hashes": len(set(hashes)),
                "hash_distribution": {hash_val: hashes.count(hash_val) for hash_val in set(hashes)}
            },
            "summary": self._generate_comparison_summary(successful_results, fastest, slowest, data_consistent)
        }
    
    def _generate_comparison_summary(self, results, fastest, slowest, data_consistent):
        """生成对比总结"""
        summary = []
        
        if fastest[0] != slowest[0]:
            speedup = slowest[1]["build_time"] / fastest[1]["build_time"]
            summary.append(f"{fastest[0]} 比 {slowest[0]} 快 {speedup:.1f}x")
        
        if data_consistent:
            summary.append("所有构建器产生一致的结果")
        else:
            summary.append("⚠️ 不同构建器产生了不同的结果")
        
        # 功能特性对比
        all_features = set()
        for result in results.values():
            all_features.update(result["builder_info"]["features"])
        
        feature_comparison = {}
        for name, result in results.items():
            builder_features = set(result["builder_info"]["features"])
            feature_comparison[name] = {
                "unique_features": list(builder_features - (all_features - builder_features)),
                "total_features": len(builder_features)
            }
        
        return {
            "performance_summary": summary,
            "feature_comparison": feature_comparison
        }
    
    def _record_build(self, builder_name: str, build_time: float, result_count: int, error: str = None):
        """记录构建历史"""
        record = {
            "timestamp": datetime.now(),
            "builder": builder_name,
            "build_time": build_time,
            "result_count": result_count,
            "success": error is None,
            "error": error
        }
        
        self.build_history.append(record)
        
        # 保持历史记录数量在合理范围内
        if len(self.build_history) > 100:
            self.build_history = self.build_history[-50:]
    
    def get_build_statistics(self) -> Dict[str, Any]:
        """获取构建统计信息"""
        if not self.build_history:
            return {"message": "没有构建历史"}
        
        successful_builds = [record for record in self.build_history if record["success"]]
        failed_builds = [record for record in self.build_history if not record["success"]]
        
        stats = {
            "total_builds": len(self.build_history),
            "successful_builds": len(successful_builds),
            "failed_builds": len(failed_builds),
            "success_rate": len(successful_builds) / len(self.build_history) * 100
        }
        
        if successful_builds:
            build_times = [record["build_time"] for record in successful_builds]
            stats.update({
                "average_build_time": sum(build_times) / len(build_times),
                "min_build_time": min(build_times),
                "max_build_time": max(build_times)
            })
        
        # 按构建器分组统计
        builder_stats = {}
        for record in self.build_history:
            builder = record["builder"]
            if builder not in builder_stats:
                builder_stats[builder] = {"builds": 0, "successes": 0, "total_time": 0}
            
            builder_stats[builder]["builds"] += 1
            if record["success"]:
                builder_stats[builder]["successes"] += 1
                builder_stats[builder]["total_time"] += record["build_time"]
        
        stats["builder_performance"] = builder_stats
        return stats


# 全局适配器实例
_default_adapter = None


def get_graph_builder_adapter(preferred_builder: str = "auto") -> GraphBuilderAdapter:
    """获取适配器实例（单例模式）"""
    global _default_adapter
    if _default_adapter is None:
        _default_adapter = GraphBuilderAdapter(preferred_builder)
    return _default_adapter


def build_transaction_call_graph_adapter(
    target_contract: str, 
    start_block: int, 
    end_block: int, 
    max_depth: int = 3,
    pruning_enabled: bool = True,
    related_addresses: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    适配器函数接口 - 与原有函数完全兼容
    
    Args:
        target_contract: 目标合约地址
        start_block: 起始区块
        end_block: 结束区块
        max_depth: 最大递归深度
        pruning_enabled: 是否启用剪枝
        related_addresses: 相关地址列表
        
    Returns:
        交易调用图字典
    """
    adapter = get_graph_builder_adapter()
    return adapter.build_transaction_call_graph(
        target_contract, start_block, end_block, max_depth, pruning_enabled, related_addresses
    ) 