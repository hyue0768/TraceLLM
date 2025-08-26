#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
call_tree_builder.py - 调用树构建模块

基于选中的Top-K可疑路径重建调用树，并提取路径节点的K邻域
参考gnn_path_detection/data_builder.py的调用树构建逻辑
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)


class CallTreeNode:
    """调用树节点类 - 扩展版本"""
    
    def __init__(self, method: str = "", depth: int = 0, node_id: int = 0):
        self.method = method  # 当前步的方法名
        self.depth = depth    # 节点深度
        self.node_id = node_id  # 全局节点ID
        self.children = {}    # method -> CallTreeNode
        self.parent = None    # 父节点
        self.is_leaf = False  # 是否叶节点
        self.path_info = {}   # 如果是叶节点，存储路径信息(path_id, label等)
        
        # 扩展属性
        self.is_suspicious_path = False  # 是否属于可疑路径
        self.related_path_ids = set()    # 经过此节点的路径ID集合
        self.suspicious_path_ids = set() # 经过此节点的可疑路径ID集合
        
    def add_child(self, method: str, node_id: int) -> 'CallTreeNode':
        """添加子节点"""
        if method not in self.children:
            child = CallTreeNode(method, self.depth + 1, node_id)
            child.parent = self
            self.children[method] = child
        return self.children[method]
    
    def get_fanout(self) -> int:
        """获取出度"""
        return len(self.children)
    
    def get_all_neighbors(self) -> Set['CallTreeNode']:
        """获取所有邻居节点（父节点 + 所有子节点）"""
        neighbors = set()
        
        # 添加父节点
        if self.parent:
            neighbors.add(self.parent)
        
        # 添加所有子节点
        neighbors.update(self.children.values())
        
        return neighbors
    
    def get_k_neighbors(self, k: int) -> Set['CallTreeNode']:
        """
        获取K层邻域内的所有节点（BFS方式）
        
        Args:
            k: 邻域层数，如果k=0则返回空集合
            
        Returns:
            K层邻域内的所有节点集合（不包括起始节点本身）
        """
        if k == 0:
            return set()
        
        neighbors = set()
        visited = {self}  # 已访问节点
        queue = deque([(self, 0)])  # (节点, 距离)
        
        while queue:
            current_node, distance = queue.popleft()
            
            # 如果不是起始节点且在K层范围内，添加到邻居集合
            if distance > 0:
                neighbors.add(current_node)
            
            # 继续BFS，如果距离小于K则继续扩展
            if distance < k:
                # 添加父节点
                if current_node.parent and current_node.parent not in visited:
                    visited.add(current_node.parent)
                    queue.append((current_node.parent, distance + 1))
                
                # 添加子节点
                for child in current_node.children.values():
                    if child not in visited:
                        visited.add(child)
                        queue.append((child, distance + 1))
        
        return neighbors
    
    def mark_as_suspicious(self, path_id: str):
        """标记节点属于可疑路径"""
        self.is_suspicious_path = True
        self.suspicious_path_ids.add(path_id)
    
    def add_path_id(self, path_id: str):
        """添加经过此节点的路径ID"""
        self.related_path_ids.add(path_id)


class TransactionCallTree:
    """单个交易的调用树 - 扩展版本"""
    
    def __init__(self, tx_hash: str):
        self.tx_hash = tx_hash
        self.root = CallTreeNode("ROOT", 0, 0)  # 根节点
        self.nodes = [self.root]  # 所有节点列表，索引即node_id
        self.path_to_leaf = {}    # path_id -> leaf_node 映射
        self.path_to_nodes = {}   # path_id -> [节点列表] 映射
        self.node_count = 1       # 节点计数器
        self.suspicious_path_ids = set()  # 可疑路径ID集合
        
    def add_path(self, path_data: Dict) -> CallTreeNode:
        """
        添加一个路径到调用树
        
        Args:
            path_data: 包含path_id, methods_str, label等的字典
            
        Returns:
            添加的叶节点
        """
        path_id = path_data['path_id']
        methods_str = str(path_data.get('methods_str', '')).strip()
        
        # 解析方法序列
        if methods_str and methods_str not in ['', 'nan', 'None']:
            methods = [m.strip() for m in methods_str.split('|') if m.strip()]
        else:
            methods = []
        
        # 从根节点开始，沿路径构建节点
        current = self.root
        path_nodes = [current]  # 记录路径经过的所有节点
        
        # 根节点也要记录路径信息
        current.add_path_id(path_id)
        
        for method in methods:
            if method not in current.children:
                # 创建新节点
                current.add_child(method, self.node_count)
                self.nodes.append(current.children[method])
                self.node_count += 1
            current = current.children[method]
            current.add_path_id(path_id)
            path_nodes.append(current)
        
        # 设置叶节点信息
        current.is_leaf = True
        current.path_info = path_data.copy()
        self.path_to_leaf[path_id] = current
        self.path_to_nodes[path_id] = path_nodes
        
        return current
    
    def mark_suspicious_paths(self, suspicious_path_ids: List[str]):
        """
        标记可疑路径
        
        Args:
            suspicious_path_ids: 可疑路径ID列表
        """
        self.suspicious_path_ids = set(suspicious_path_ids)
        
        for path_id in suspicious_path_ids:
            if path_id in self.path_to_nodes:
                # 标记路径上的所有节点为可疑
                for node in self.path_to_nodes[path_id]:
                    node.mark_as_suspicious(path_id)
        
        logger.debug(f"交易 {self.tx_hash}: 标记了 {len(suspicious_path_ids)} 条可疑路径")
    
    def get_path_context(self, path_id: str, k: int) -> Dict[str, Any]:
        """
        获取路径的上下文信息（路径节点 + K层邻域）
        
        Args:
            path_id: 路径ID
            k: 邻域层数
            
        Returns:
            路径上下文字典
        """
        if path_id not in self.path_to_nodes:
            return {}
        
        path_nodes = self.path_to_nodes[path_id]
        context_nodes = set(path_nodes)  # 路径节点
        
        # 为路径上的每个节点收集K层邻域
        for node in path_nodes:
            neighbors = node.get_k_neighbors(k)
            context_nodes.update(neighbors)
        
        # 构建上下文子图的边
        context_edges = []
        for node in context_nodes:
            # 添加与其他上下文节点的边
            if node.parent and node.parent in context_nodes:
                context_edges.append((node.parent.node_id, node.node_id))
            
            for child in node.children.values():
                if child in context_nodes:
                    context_edges.append((node.node_id, child.node_id))
        
        # 统计邻域层数分布
        layer_distribution = {}
        for node in path_nodes:
            # 为每个路径节点计算其邻域节点的层数分布
            visited = {node}
            queue = deque([(node, 0)])
            
            while queue:
                current_node, distance = queue.popleft()
                
                if distance > 0 and distance <= k:
                    layer = distance
                    if layer not in layer_distribution:
                        layer_distribution[layer] = 0
                    layer_distribution[layer] += 1
                
                if distance < k:
                    if current_node.parent and current_node.parent not in visited:
                        visited.add(current_node.parent)
                        queue.append((current_node.parent, distance + 1))
                    
                    for child in current_node.children.values():
                        if child not in visited:
                            visited.add(child)
                            queue.append((child, distance + 1))
        
        return {
            'path_id': path_id,
            'path_nodes': [node.node_id for node in path_nodes],
            'context_nodes': [node.node_id for node in context_nodes],
            'context_edges': context_edges,
            'k_layers': k,
            'layer_distribution': layer_distribution,
            'node_details': {
                node.node_id: {
                    'method': node.method,
                    'depth': node.depth,
                    'is_leaf': node.is_leaf,
                    'is_suspicious': node.is_suspicious_path,
                    'fanout': node.get_fanout(),
                    'path_info': node.path_info if node.is_leaf else None,
                    'related_paths': list(node.related_path_ids),
                    'suspicious_paths': list(node.suspicious_path_ids)
                }
                for node in context_nodes
            }
        }
    
    def get_path_context_with_expansion(self, path_id: str, k: int) -> Dict[str, Any]:
        """
        获取路径的K层路径扩展上下文（k-layer closure subgraph）
        
        实现k-layer closure subgraph定义：
        - k=0: 只包含异常路径本身
        - k=1: 对路径上每个节点，添加其one-hop邻居，扩展生成新路径
        - k=2: 对k=1生成的新路径，继续扩展其末端节点的one-hop邻居
        - 以此类推，迭代扩展到k层
        
        例如：
        - 异常路径 A→B→E  
        - K=0: {A→B→E}
        - K=1: {A→B→E, A→C, A→D, A→B→F} (从A,B,E扩展)
        - K=2: {A→B→E, A→C→G, A→D, A→B→F} (从C扩展)
        
        Args:
            path_id: 目标异常路径ID  
            k: 路径扩展层数
            
        Returns:
            路径扩展上下文信息
        """
        if path_id not in self.path_to_nodes:
            return {}
        
        target_path_nodes = self.path_to_nodes[path_id]
        if not target_path_nodes:
            return {}
        
        # 将节点路径转换为方法序列，便于扩展
        target_methods = [node.method for node in target_path_nodes]
        
        # 当前层的所有路径：{生成的路径字符串: [节点列表]}
        current_paths = {
            f"{path_id}_original": target_path_nodes
        }
        
        # 记录所有生成的路径
        all_generated_paths = {f"{path_id}_original": target_path_nodes}
        layer_path_counts = {0: 1}
        
        if k > 0:
            # 第一层：从原始路径的每个节点扩展one-hop邻居
            if k >= 1:
                new_paths = {}
                
                # 对原始路径上的每个节点进行扩展
                for i, node in enumerate(target_path_nodes):
                    # 扩展该节点的所有子节点，生成新路径
                    for child_method, child_node in node.children.items():
                        # 创建从根到该扩展节点的完整路径
                        if i == 0:
                            # 从根节点扩展
                            extended_path_nodes = [node, child_node]
                        else:
                            # 从路径中间节点扩展：保留到该节点的路径，然后添加扩展
                            extended_path_nodes = target_path_nodes[:i+1] + [child_node]
                        
                        extended_path_key = f"{path_id}_k1_from_{node.method}_to_{child_method}"
                        
                        # 避免与原始路径重复，且避免重复扩展
                        if (extended_path_key not in all_generated_paths and 
                            extended_path_nodes != target_path_nodes):
                            new_paths[extended_path_key] = extended_path_nodes
                            all_generated_paths[extended_path_key] = extended_path_nodes
                
                layer_path_counts[1] = len(new_paths)
                current_paths = new_paths
                
                logger.info(f"路径 {path_id}: K=1层扩展生成 {len(new_paths)} 条新路径，总路径数 {len(all_generated_paths)}")
                if new_paths:
                    logger.info(f"  新增路径: {list(new_paths.keys())[:3]}...")
            
            # 后续层：从前一层生成的路径继续扩展
            for layer in range(2, k + 1):
                if not current_paths:
                    break
                    
                new_paths = {}
                
                # 对当前层的每条路径进行扩展
                for current_path_key, current_path_nodes in current_paths.items():
                    # 从末端节点扩展
                    leaf_node = current_path_nodes[-1]
                    
                    # 扩展末端节点的所有子节点
                    for child_method, child_node in leaf_node.children.items():
                        # 创建扩展路径
                        extended_path_nodes = current_path_nodes + [child_node]
                        extended_path_key = f"{current_path_key}_k{layer}_{child_method}"
                        
                        # 避免重复路径
                        if extended_path_key not in all_generated_paths:
                            new_paths[extended_path_key] = extended_path_nodes
                            all_generated_paths[extended_path_key] = extended_path_nodes
                
                layer_path_counts[layer] = len(new_paths)
                current_paths = new_paths
                
                # 调试信息：记录每层找到的路径数量
                logger.info(f"路径 {path_id}: K={layer}层扩展生成 {len(new_paths)} 条新路径，总路径数 {len(all_generated_paths)}")
                if new_paths:
                    logger.info(f"  新增路径: {list(new_paths.keys())[:3]}...")
                
                if not new_paths:  # 没有更多可扩展的路径
                    logger.info(f"路径 {path_id}: 在第{layer}层没有找到更多可扩展路径，提前结束")
                    break
        
        # 收集所有生成路径中的节点
        all_nodes = set()
        for path_nodes in all_generated_paths.values():
            all_nodes.update(path_nodes)
        
        # 构建路径间的连接关系（扩展路径的父子关系）
        path_connections = []
        for path_key_1, nodes_1 in all_generated_paths.items():
            for path_key_2, nodes_2 in all_generated_paths.items():
                if path_key_1 >= path_key_2:  # 避免重复
                    continue
                # 检查是否是扩展关系（一个路径是另一个的前缀）
                if len(nodes_1) < len(nodes_2):
                    if nodes_2[:len(nodes_1)] == nodes_1:
                        path_connections.append((path_key_1, path_key_2))
                elif len(nodes_2) < len(nodes_1):
                    if nodes_1[:len(nodes_2)] == nodes_2:
                        path_connections.append((path_key_2, path_key_1))
        
        # 构建完整的边关系
        all_edges = []
        for node in all_nodes:
            if node.parent and node.parent in all_nodes:
                all_edges.append((node.parent.node_id, node.node_id))
        
        return {
            'target_path_id': path_id,
            'k_layers': k,
            'related_paths': {
                path_key: [node.node_id for node in nodes] 
                for path_key, nodes in all_generated_paths.items()
            },
            'path_connections': path_connections,
            'all_nodes': [node.node_id for node in all_nodes],
            'all_edges': all_edges,
            'layer_statistics': {
                'total_paths': len(all_generated_paths),
                'total_nodes': len(all_nodes),
                'target_path_length': len(target_path_nodes),
                'expansion_layers': k,
                'layer_path_counts': layer_path_counts,
                'actual_expansion_depth': max(layer_path_counts.keys()) if layer_path_counts else 0
            },
            'node_details': {
                node.node_id: {
                    'method': node.method,
                    'depth': node.depth,
                    'is_leaf': node.is_leaf,
                    'is_suspicious': node.is_suspicious_path,
                    'fanout': node.get_fanout(),
                    'path_info': node.path_info if node.is_leaf else None,
                    'in_paths': [path_key for path_key, pnodes in all_generated_paths.items() if node in pnodes]
                } for node in all_nodes
            },
            'path_details': {
                path_key: {
                    'nodes': [node.node_id for node in nodes],
                    'methods': [node.method for node in nodes],
                    'is_target': path_key.endswith('_original'),
                    'length': len(nodes),
                    'generation_layer': 0 if path_key.endswith('_original') else int(path_key.split('_ext_')[1].split('_')[0]) if '_ext_' in path_key else 0
                } for path_key, nodes in all_generated_paths.items()
            }
        }
    
    def get_all_suspicious_contexts(self, k: int) -> Dict[str, Dict]:
        """
        获取所有可疑路径的上下文
        
        Args:
            k: 邻居数量
            
        Returns:
            {path_id: context_dict}
        """
        contexts = {}
        for path_id in self.suspicious_path_ids:
            contexts[path_id] = self.get_path_context(path_id, k)
        return contexts
    
    def get_edges(self) -> List[Tuple[int, int]]:
        """获取有向边列表 [(parent_id, child_id), ...]"""
        edges = []
        
        def dfs(node):
            for child in node.children.values():
                edges.append((node.node_id, child.node_id))
                dfs(child)
        
        dfs(self.root)
        return edges
    
    def get_tree_statistics(self) -> Dict[str, Any]:
        """获取调用树统计信息"""
        total_nodes = len(self.nodes)
        leaf_nodes = sum(1 for node in self.nodes if node.is_leaf)
        suspicious_nodes = sum(1 for node in self.nodes if node.is_suspicious_path)
        max_depth = max(node.depth for node in self.nodes) if self.nodes else 0
        
        return {
            'tx_hash': self.tx_hash,
            'total_nodes': total_nodes,
            'leaf_nodes': leaf_nodes,
            'suspicious_nodes': suspicious_nodes,
            'max_depth': max_depth,
            'total_paths': len(self.path_to_nodes),
            'suspicious_paths': len(self.suspicious_path_ids)
        }


class CallTreeBuilder:
    """调用树构建器"""
    
    def __init__(self):
        self.tx_trees = {}  # tx_hash -> TransactionCallTree
        
    def build_transaction_trees(self, df: pd.DataFrame) -> Dict[str, TransactionCallTree]:
        """
        为每个交易构建调用树
        
        Args:
            df: 路径数据DataFrame
            
        Returns:
            {tx_hash: TransactionCallTree}
        """
        logger.info("构建交易调用树...")
        
        tx_trees = {}
        
        for tx_hash, tx_group in df.groupby('tx_hash'):
            tree = TransactionCallTree(tx_hash)
            
            # 为当前交易的每个路径添加到树中
            for _, row in tx_group.iterrows():
                path_data = {
                    'path_id': row['path_id'],
                    'methods_str': row.get('methods_str', ''),
                    'label': int(row.get('label', 0)),
                    'path_length': int(row.get('path_length', 0)),
                    'max_depth': self._safe_float(row.get('max_depth', 0)),
                    'method_count': self._safe_float(row.get('method_count', 0)),
                    'address_count': self._safe_float(row.get('address_count', 0)),
                    'total_value': self._safe_float(row.get('total_value', 0)),
                    'contains_create': self._safe_bool(row.get('contains_create', 0)),
                    'contains_transfer': self._safe_bool(row.get('contains_transfer', 0)),
                    'contains_swap': self._safe_bool(row.get('contains_swap', 0)),
                    'contains_approve': self._safe_bool(row.get('contains_approve', 0)),
                    # 添加更多可能的特征
                    'event_name': row.get('event_name', 'unknown'),
                    'attacker_address': row.get('attacker_address', 'unknown'),
                    'source_file': row.get('source_file', 'unknown')
                }
                tree.add_path(path_data)
            
            tx_trees[tx_hash] = tree
        
        self.tx_trees = tx_trees
        logger.info(f"构建了 {len(tx_trees)} 个交易调用树")
        return tx_trees
    
    def mark_suspicious_paths_in_trees(self, suspicious_results: Dict[str, List[str]]):
        """
        在调用树中标记可疑路径
        
        Args:
            suspicious_results: {source_file: [path_ids]} 来自LR分析器的结果
        """
        logger.info("标记可疑路径...")
        
        total_marked = 0
        
        for tx_hash, tree in self.tx_trees.items():
            # 找到属于这个交易的可疑路径
            tx_suspicious_paths = []
            
            for source_file, path_ids in suspicious_results.items():
                for path_id in path_ids:
                    if path_id in tree.path_to_nodes:
                        tx_suspicious_paths.append(path_id)
            
            if tx_suspicious_paths:
                tree.mark_suspicious_paths(tx_suspicious_paths)
                total_marked += len(tx_suspicious_paths)
        
        logger.info(f"总共标记了 {total_marked} 条可疑路径")
    
    def extract_path_contexts(self, suspicious_results: Dict[str, List[str]], 
                            k: int) -> Dict[str, Dict[str, Dict]]:
        """
        提取所有可疑路径的上下文
        
        Args:
            suspicious_results: {source_file: [path_ids]} 来自LR分析器的结果
            k: 邻居数量
            
        Returns:
            {source_file: {path_id: context_dict}}
        """
        logger.info(f"提取可疑路径上下文，K={k}...")
        
        # 先标记可疑路径
        self.mark_suspicious_paths_in_trees(suspicious_results)
        
        all_contexts = {}
        
        for source_file, path_ids in suspicious_results.items():
            file_contexts = {}
            
            for path_id in path_ids:
                # 找到包含此路径的交易
                found = False
                for tx_hash, tree in self.tx_trees.items():
                    if path_id in tree.path_to_nodes:
                        context = tree.get_path_context_with_expansion(path_id, k)
                        if context:
                            context['tx_hash'] = tx_hash
                            context['source_file'] = source_file
                            file_contexts[path_id] = context
                            found = True
                            logger.debug(f"路径 {path_id}: K={k}层扩展找到 {context['layer_statistics']['total_paths']} 条相关路径")
                        break
                
                if not found:
                    logger.warning(f"路径 {path_id} 未找到对应的调用树")
            
            if file_contexts:
                all_contexts[source_file] = file_contexts
                logger.info(f"文件 {source_file}: 提取了 {len(file_contexts)} 个路径上下文")
        
        total_contexts = sum(len(contexts) for contexts in all_contexts.values())
        logger.info(f"总共提取了 {total_contexts} 个路径上下文")
        
        return all_contexts
    
    def get_global_statistics(self) -> Dict[str, Any]:
        """获取全局统计信息"""
        if not self.tx_trees:
            return {}
        
        stats = []
        for tree in self.tx_trees.values():
            stats.append(tree.get_tree_statistics())
        
        total_nodes = sum(s['total_nodes'] for s in stats)
        total_paths = sum(s['total_paths'] for s in stats)
        total_suspicious = sum(s['suspicious_paths'] for s in stats)
        max_depth = max(s['max_depth'] for s in stats) if stats else 0
        
        return {
            'total_transactions': len(self.tx_trees),
            'total_nodes': total_nodes,
            'total_paths': total_paths,
            'total_suspicious_paths': total_suspicious,
            'max_depth': max_depth,
            'avg_nodes_per_tx': total_nodes / len(self.tx_trees) if self.tx_trees else 0,
            'avg_paths_per_tx': total_paths / len(self.tx_trees) if self.tx_trees else 0
        }
    
    def _safe_float(self, value) -> float:
        """安全转换为float"""
        if value is None or value == '':
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            value = value.strip().lower()
            if value in ['', 'nan', 'none', 'null']:
                return 0.0
            try:
                return float(value)
            except ValueError:
                return 0.0
        return 0.0
    
    def _safe_bool(self, value) -> bool:
        """安全转换为bool"""
        if value is None or value == '':
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            value = value.strip().lower()
            return value in ['true', '1', 'yes']
        return False


def format_path_context_for_display(context: Dict[str, Any], 
                                   show_neighbors: bool = True) -> str:
    """
    格式化路径上下文用于显示
    
    Args:
        context: 路径上下文字典
        show_neighbors: 是否显示邻居节点详情
        
    Returns:
        格式化的字符串
    """
    if not context:
        return "空上下文"
    
    lines = []
    lines.append(f"路径ID: {context['path_id']}")
    lines.append(f"交易Hash: {context.get('tx_hash', 'unknown')}")
    lines.append(f"源文件: {context.get('source_file', 'unknown')}")
    
    path_nodes = context['path_nodes']
    context_nodes = context['context_nodes']
    node_details = context['node_details']
    
    lines.append(f"路径节点数: {len(path_nodes)}")
    lines.append(f"上下文节点数: {len(context_nodes)}")
    lines.append(f"边数: {len(context.get('context_edges', []))}")
    
    # 显示路径序列
    path_methods = []
    for node_id in path_nodes:
        if node_id in node_details:
            method = node_details[node_id]['method']
            if method == "ROOT":
                path_methods.append("ROOT")
            else:
                path_methods.append(method)
    
    lines.append(f"路径序列: {' -> '.join(path_methods)}")
    
    if show_neighbors:
        # 显示邻居节点（非路径节点）
        neighbor_nodes = [nid for nid in context_nodes if nid not in path_nodes]
        if neighbor_nodes:
            lines.append(f"邻居节点 ({len(neighbor_nodes)} 个):")
            for node_id in neighbor_nodes[:5]:  # 只显示前5个
                if node_id in node_details:
                    detail = node_details[node_id]
                    lines.append(f"  - 节点{node_id}: {detail['method']} (深度:{detail['depth']}, 出度:{detail['fanout']})")
            if len(neighbor_nodes) > 5:
                lines.append(f"  ... 还有 {len(neighbor_nodes) - 5} 个邻居节点")
    
    return "\n".join(lines)


if __name__ == "__main__":
    # 简单测试
    import sys
    sys.path.append('/home/os/shuzheng/whole_pipeline')
    from utils_scoring import parse_csv
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # 测试数据
    test_file = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled/event_event_2_Barley_Finance_0x356e7481_20250806_104404_labeled.csv"
    
    try:
        df = parse_csv(test_file)
        df['source_file'] = 'test_file'
        
        # 构建调用树
        builder = CallTreeBuilder()
        trees = builder.build_transaction_trees(df[:50])  # 测试前50行
        
        # 模拟可疑路径结果
        suspicious_results = {
            'test_file': list(df['path_id'].head(5))  # 前5个路径作为可疑路径
        }
        
        # 提取上下文
        contexts = builder.extract_path_contexts(suspicious_results, k=3)
        
        print(f"构建了 {len(trees)} 个调用树")
        print(f"提取了 {sum(len(c) for c in contexts.values())} 个路径上下文")
        
        # 显示第一个上下文的详情
        if contexts:
            first_file = list(contexts.keys())[0]
            first_context = list(contexts[first_file].values())[0]
            print("\n第一个路径上下文:")
            print(format_path_context_for_display(first_context))
        
        # 显示全局统计
        stats = builder.get_global_statistics()
        print(f"\n全局统计: {stats}")
        
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()