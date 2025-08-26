#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
调用路径分析器
用于从重建的调用层次结构中提取和评分最异常的调用路径
"""

import json
from typing import List, Dict, Tuple, Any, Set
from collections import defaultdict, Counter


class CallPath:
    """表示一条调用路径"""
    
    def __init__(self, nodes: List[Dict], tx_hash: str):
        self.nodes = nodes  # 路径中的节点列表
        self.tx_hash = tx_hash  # 所属交易哈希
        self.depth = len(nodes) - 1 if len(nodes) > 0 else 0  # 路径深度（边数）
        self.fanout = 0  # 扇出节点数，后续计算
        self.frequency = 1  # 路径频率，后续计算
        self.score = 0.0  # 最终评分
        
    def __str__(self) -> str:
        """返回路径的字符串表示"""
        path_str = " -> ".join([
            f"{node.get('to', 'unknown')}:{node.get('method', node.get('method_id', 'unknown'))}"
            for node in self.nodes
        ])
        return f"TX({self.tx_hash[:8]}...): {path_str}"
    
    def get_path_signature(self) -> str:
        """获取路径签名，用于识别相同的路径模式"""
        signature_parts = []
        for node in self.nodes:
            # 使用合约地址和方法名作为签名
            contract = node.get('to', 'unknown')
            method = node.get('method', node.get('method_id', 'unknown'))
            signature_parts.append(f"{contract}:{method}")
        return " -> ".join(signature_parts)


class CallPathAnalyzer:
    """调用路径分析器"""
    
    def __init__(self, alpha: float = 0.35, beta: float = 0.35, gamma: float = 0.3):
        """
        初始化分析器
        
        Args:
            alpha: 深度权重
            beta: 扇出权重  
            gamma: 频率权重
        """
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        
    def extract_all_paths_from_call_graph(self, call_graph: Dict) -> List[CallPath]:
        """
        从调用图中提取所有路径
        
        Args:
            call_graph: 包含多个交易的调用图
            
        Returns:
            所有路径的列表
        """
        all_paths = []
        
        for tx_hash, tx_data in call_graph.items():
            # 优先使用重建后的调用层次结构
            call_hierarchy = tx_data.get('rebuilt_call_hierarchy') or tx_data.get('call_hierarchy')
            
            if call_hierarchy:
                tx_paths = self.extract_paths_from_hierarchy(call_hierarchy, tx_hash)
                all_paths.extend(tx_paths)
                
        return all_paths
    
    def extract_paths_from_hierarchy(self, root_node: Dict, tx_hash: str) -> List[CallPath]:
        """
        从单个调用层次结构中提取所有路径
        
        Args:
            root_node: 根节点
            tx_hash: 交易哈希
            
        Returns:
            该交易中的所有路径
        """
        paths = []
        
        def dfs(node: Dict, current_path: List[Dict]):
            """深度优先搜索提取路径"""
            current_path = current_path + [node]
            
            # 获取子调用
            children = node.get('children', [])
            
            if not children:
                # 叶子节点，创建路径
                if len(current_path) > 1:  # 至少包含两个节点才算有效路径
                    path = CallPath(current_path.copy(), tx_hash)
                    paths.append(path)
            else:
                # 非叶子节点，继续遍历子节点
                for child in children:
                    dfs(child, current_path)
        
        # 从根节点开始遍历
        if isinstance(root_node, dict):
            dfs(root_node, [])
        elif isinstance(root_node, list):
            # 如果根是列表，遍历每个根节点
            for root in root_node:
                dfs(root, [])
                
        return paths
    
    def calculate_fanout_scores(self, paths: List[CallPath]) -> None:
        """
        计算每条路径的扇出分数
        
        Args:
            paths: 路径列表
        """
        for path in paths:
            fanout_sum = 0
            # 计算路径中所有中间节点的出度之和（不包括叶子节点）
            for i, node in enumerate(path.nodes[:-1]):  # 排除最后一个节点（叶子节点）
                children = node.get('children', [])
                fanout_sum += len(children)
            path.fanout = fanout_sum
    
    def calculate_frequency_scores(self, paths: List[CallPath]) -> None:
        """
        计算路径频率分数
        
        Args:
            paths: 路径列表
        """
        # 统计路径签名的频率
        signature_counts = Counter()
        for path in paths:
            signature = path.get_path_signature()
            signature_counts[signature] += 1
        
        # 设置每条路径的频率
        for path in paths:
            signature = path.get_path_signature()
            path.frequency = signature_counts[signature]
    
    def normalize_and_score_paths(self, paths: List[CallPath]) -> None:
        """
        归一化并计算路径评分
        
        Args:
            paths: 路径列表
        """
        if not paths:
            return
            
        # 获取最大值用于归一化
        max_depth = max(path.depth for path in paths) if paths else 1
        max_fanout = max(path.fanout for path in paths) if paths else 1
        max_frequency = max(path.frequency for path in paths) if paths else 1
        min_frequency = min(path.frequency for path in paths) if paths else 1
        
        # 避免除零错误
        max_depth = max(max_depth, 1)
        max_fanout = max(max_fanout, 1)
        frequency_range = max(max_frequency - min_frequency, 1)
        
        # 计算归一化评分
        for path in paths:
            normalized_depth = path.depth / max_depth
            normalized_fanout = path.fanout / max_fanout
            
            # 频率归一化：频率越高评分越高
            normalized_frequency = (path.frequency - min_frequency) / frequency_range
            
            # 计算最终评分
            path.score = (
                self.alpha * normalized_depth +
                self.beta * normalized_fanout +
                self.gamma * normalized_frequency
            )
    
    def get_top_suspicious_paths(self, call_graph: Dict, k: int = 5) -> List[CallPath]:
        """
        获取前K条最可疑的路径
        
        Args:
            call_graph: 调用图
            k: 返回的路径数量
            
        Returns:
            按评分排序的前K条不重复路径
        """
        # 1. 提取所有路径
        all_paths = self.extract_all_paths_from_call_graph(call_graph)
        
        if not all_paths:
            return []
        
        # 2. 计算扇出分数
        self.calculate_fanout_scores(all_paths)
        
        # 3. 计算频率分数
        self.calculate_frequency_scores(all_paths)
        
        # 4. 归一化并计算最终评分
        self.normalize_and_score_paths(all_paths)
        
        # 5. 按评分降序排序
        sorted_paths = sorted(all_paths, key=lambda p: p.score, reverse=True)
        
        # 6. 去重：保留评分最高的不重复路径
        unique_paths = []
        seen_signatures = set()
        
        for path in sorted_paths:
            signature = path.get_path_signature()
            if signature not in seen_signatures:
                unique_paths.append(path)
                seen_signatures.add(signature)
                # 达到所需数量后停止
                if len(unique_paths) >= k:
                    break
        
        return unique_paths
    
    def format_paths_for_llm(self, paths: List[CallPath]) -> Dict:
        """
        将路径格式化为适合LLM分析的格式
        
        Args:
            paths: 路径列表
            
        Returns:
            格式化后的数据
        """
        if not paths:
            return {
                "summary": "未发现可疑调用路径",
                "paths": [],
                "statistics": {
                    "total_paths": 0,
                    "transactions_involved": 0
                }
            }
        
        formatted_paths = []
        tx_hashes = set()
        
        for i, path in enumerate(paths, 1):
            tx_hashes.add(path.tx_hash)
            
            # 格式化路径节点
            formatted_nodes = []
            for j, node in enumerate(path.nodes):
                formatted_node = {
                    "step": j + 1,
                    "contract": node.get('to', 'unknown'),
                    "method": node.get('method', node.get('method_id', 'unknown')),
                    "value": node.get('value', '0'),
                    "gas": node.get('gas', 'unknown'),
                    "depth": node.get('depth', j)
                }
                formatted_nodes.append(formatted_node)
            
            formatted_path = {
                "rank": i,
                "score": round(path.score, 4),
                "transaction": path.tx_hash,
                "path_depth": path.depth,
                "fanout_score": path.fanout,
                "frequency": path.frequency,
                "call_sequence": formatted_nodes,
                "summary": f"TX {path.tx_hash[:8]}... -> {len(path.nodes)} 步调用，深度 {path.depth}"
            }
            formatted_paths.append(formatted_path)
        
        return {
            "summary": f"检测到 {len(paths)} 条最可疑的调用路径",
            "paths": formatted_paths,
            "statistics": {
                "total_paths": len(paths),
                "transactions_involved": len(tx_hashes),
                "avg_score": round(sum(p.score for p in paths) / len(paths), 4),
                "max_depth": max(p.depth for p in paths),
                "max_fanout": max(p.fanout for p in paths)
            },
            "scoring_weights": {
                "depth_weight": self.alpha,
                "fanout_weight": self.beta,
                "frequency_weight": self.gamma
            }
        }


def analyze_suspicious_call_paths(call_graph: Dict, k: int = 5, 
                                alpha: float = 0.4, beta: float = 0.4, gamma: float = 0.2) -> Dict:
    """
    分析可疑调用路径的主函数
    
    Args:
        call_graph: 调用图数据
        k: 返回的可疑路径数量
        alpha: 深度权重
        beta: 扇出权重
        gamma: 频率权重
        
    Returns:
        格式化的分析结果
    """
    analyzer = CallPathAnalyzer(alpha=alpha, beta=beta, gamma=gamma)
    suspicious_paths = analyzer.get_top_suspicious_paths(call_graph, k=k)
    return analyzer.format_paths_for_llm(suspicious_paths)


if __name__ == "__main__":
    # 测试代码
    test_call_graph = {
        "0x123...": {
            "rebuilt_call_hierarchy": {
                "to": "0xcontract1",
                "method": "function1",
                "children": [
                    {
                        "to": "0xcontract2", 
                        "method": "function2",
                        "children": [
                            {"to": "0xcontract3", "method": "function3", "children": []},
                            {"to": "0xcontract4", "method": "function4", "children": []}
                        ]
                    }
                ]
            }
        }
    }
    
    result = analyze_suspicious_call_paths(test_call_graph, k=3)
    print(json.dumps(result, indent=2, ensure_ascii=False)) 