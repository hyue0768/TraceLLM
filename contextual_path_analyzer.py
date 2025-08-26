#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
contextual_path_analyzer.py - 上下文路径分析器

整合LogisticRegressionAnalyzer和CallTreeBuilder，
为可疑路径提供丰富的上下文信息用于LLM分析
"""

import os
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import logging

from logistic_regression_analyzer import LogisticRegressionAnalyzer
from call_tree_builder import CallTreeBuilder, format_path_context_for_display

logger = logging.getLogger(__name__)


class ContextualPathAnalyzer:
    """上下文路径分析器 - 主控制器"""
    
    def __init__(self, 
                 k_paths: int = 30,
                 k_neighbors: int = 3,
                 suspicious_methods: Optional[List[str]] = None,
                 random_state: int = 42):
        """
        初始化分析器
        
        Args:
            k_paths: 选择的top可疑路径数量
            k_neighbors: 每个路径节点的邻居数量
            suspicious_methods: 可疑方法列表
            random_state: 随机种子
        """
        self.k_paths = k_paths
        self.k_neighbors = k_neighbors
        self.random_state = random_state
        
        # 初始化子模块
        self.lr_analyzer = LogisticRegressionAnalyzer(
            k=k_paths,
            suspicious_methods=suspicious_methods,
            random_state=random_state
        )
        
        self.tree_builder = CallTreeBuilder()
        
        logger.info(f"上下文路径分析器初始化完成")
        logger.info(f"  - Top-K路径: {k_paths}")
        logger.info(f"  - K邻居: {k_neighbors}")
    
    def analyze_with_context(self, input_dir: str) -> Dict[str, Any]:
        """
        执行完整的上下文分析流程
        
        Args:
            input_dir: 包含标注CSV文件的目录
            
        Returns:
            分析结果字典
        """
        logger.info("="*60)
        logger.info("开始上下文路径分析")
        logger.info("="*60)
        
        # 步骤1: 使用Logistic Regression找到可疑路径
        logger.info("步骤1: 使用Logistic Regression选择可疑路径...")
        lr_results = self.lr_analyzer.analyze_all_files(input_dir)
        
        if not lr_results['per_file_results']:
            raise ValueError("Logistic Regression分析未产生有效结果")
        
        # 提取可疑路径
        suspicious_paths = {}
        all_df_data = {}  # 存储每个文件的DataFrame数据
        
        for file_name, result in lr_results['per_file_results'].items():
            if 'top_k_path_ids' in result:
                suspicious_paths[file_name] = result['top_k_path_ids']
                # 保存DataFrame数据用于后续构建调用树
                all_df_data[file_name] = result['test_df_with_scores']
        
        total_suspicious = sum(len(paths) for paths in suspicious_paths.values())
        logger.info(f"✅ 找到 {total_suspicious} 条可疑路径，来自 {len(suspicious_paths)} 个文件")
        
        # 步骤2: 合并所有DataFrame并构建调用树
        logger.info("步骤2: 构建交易调用树...")
        all_dfs = []
        for file_name, df in all_df_data.items():
            df = df.copy()
            df['source_file'] = file_name
            all_dfs.append(df)
        
        if not all_dfs:
            raise ValueError("没有可用的DataFrame数据构建调用树")
        
        combined_df = pd.concat(all_dfs, ignore_index=True)
        tx_trees = self.tree_builder.build_transaction_trees(combined_df)
        
        # 步骤3: 提取可疑路径的上下文
        logger.info(f"步骤3: 提取K={self.k_neighbors}邻域上下文...")
        path_contexts = self.tree_builder.extract_path_contexts(
            suspicious_paths, self.k_neighbors
        )
        
        # 步骤4: 整理最终结果
        logger.info("步骤4: 整理分析结果...")
        final_results = {
            'analysis_config': {
                'k_paths': self.k_paths,
                'k_neighbors': self.k_neighbors,
                'input_dir': input_dir,
                'timestamp': datetime.now().isoformat()
            },
            'lr_analysis': lr_results,
            'suspicious_paths': suspicious_paths,
            'path_contexts': path_contexts,
            'tree_statistics': self.tree_builder.get_global_statistics(),
            'summary': self._generate_summary(lr_results, path_contexts)
        }
        
        logger.info("✅ 上下文路径分析完成")
        return final_results
    
    def _generate_summary(self, lr_results: Dict, path_contexts: Dict) -> Dict[str, Any]:
        """生成分析摘要"""
        total_files = lr_results.get('total_files', 0)
        successful_files = lr_results.get('successful_files', 0)
        
        total_suspicious_paths = sum(
            len(contexts) for contexts in path_contexts.values()
        )
        
        # 计算上下文统计
        context_stats = {
            'total_contexts': total_suspicious_paths,
            'avg_context_nodes': 0,
            'avg_neighbors': 0,
            'max_context_size': 0
        }
        
        if total_suspicious_paths > 0:
            context_node_counts = []
            neighbor_counts = []
            
            for file_contexts in path_contexts.values():
                for context in file_contexts.values():
                    context_size = len(context.get('context_nodes', []))
                    path_size = len(context.get('path_nodes', []))
                    neighbors = context_size - path_size
                    
                    context_node_counts.append(context_size)
                    neighbor_counts.append(neighbors)
            
            if context_node_counts:
                context_stats.update({
                    'avg_context_nodes': np.mean(context_node_counts),
                    'avg_neighbors': np.mean(neighbor_counts),
                    'max_context_size': np.max(context_node_counts)
                })
        
        # LR性能指标
        lr_metrics = lr_results.get('global_metrics', {})
        
        return {
            'files_processed': f"{successful_files}/{total_files}",
            'total_suspicious_paths': total_suspicious_paths,
            'lr_performance': {
                'macro_attack_hit_rate': lr_metrics.get('macro_attack_hit_rate', 0),
                'macro_f1': lr_metrics.get('macro_f1', 0),
                'micro_f1': lr_metrics.get('micro_f1', 0)
            },
            'context_statistics': context_stats
        }
    
    def save_results(self, results: Dict[str, Any], output_dir: str) -> Dict[str, str]:
        """
        保存分析结果
        
        Args:
            results: 分析结果
            output_dir: 输出目录
            
        Returns:
            保存的文件路径字典
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_files = {}
        
        # 1. 保存完整结果
        full_results_file = os.path.join(output_dir, f"contextual_analysis_full_{timestamp}.json")
        with open(full_results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        saved_files['full_results'] = full_results_file
        
        # 2. 保存可疑路径汇总
        summary_data = []
        for file_name, contexts in results['path_contexts'].items():
            for path_id, context in contexts.items():
                node_details = context.get('node_details', {})
                leaf_node_id = context['path_nodes'][-1] if context['path_nodes'] else None
                leaf_info = node_details.get(leaf_node_id, {}).get('path_info', {}) if leaf_node_id else {}
                
                summary_data.append({
                    'source_file': file_name,
                    'path_id': path_id,
                    'tx_hash': context.get('tx_hash', 'unknown'),
                    'path_length': len(context['path_nodes']),
                    'context_size': len(context['context_nodes']),
                    'neighbor_count': len(context['context_nodes']) - len(context['path_nodes']),
                    'label': leaf_info.get('label', 0),
                    'event_name': leaf_info.get('event_name', 'unknown'),
                    'attacker_address': leaf_info.get('attacker_address', 'unknown')
                })
        
        if summary_data:
            summary_df = pd.DataFrame(summary_data)
            summary_file = os.path.join(output_dir, f"suspicious_paths_summary_{timestamp}.csv")
            summary_df.to_csv(summary_file, index=False)
            saved_files['summary'] = summary_file
        
        # 3. 保存路径上下文详情（用于LLM分析）
        contexts_file = os.path.join(output_dir, f"path_contexts_{timestamp}.json")
        with open(contexts_file, 'w', encoding='utf-8') as f:
            json.dump(results['path_contexts'], f, indent=2, ensure_ascii=False, default=str)
        saved_files['contexts'] = contexts_file
        
        # 4. 保存可读格式的上下文报告
        report_file = os.path.join(output_dir, f"context_report_{timestamp}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("上下文路径分析报告\n")
            f.write("="*50 + "\n\n")
            
            # 写入摘要
            summary = results['summary']
            f.write(f"分析配置:\n")
            f.write(f"  - Top-K路径: {results['analysis_config']['k_paths']}\n")
            f.write(f"  - K邻居: {results['analysis_config']['k_neighbors']}\n")
            f.write(f"  - 输入目录: {results['analysis_config']['input_dir']}\n\n")
            
            f.write(f"处理结果:\n")
            f.write(f"  - 处理文件: {summary['files_processed']}\n")
            f.write(f"  - 可疑路径总数: {summary['total_suspicious_paths']}\n")
            f.write(f"  - LR宏平均命中率: {summary['lr_performance']['macro_attack_hit_rate']:.3f}\n")
            f.write(f"  - LR宏平均F1: {summary['lr_performance']['macro_f1']:.3f}\n\n")
            
            # 写入每个文件的上下文详情
            f.write("路径上下文详情:\n")
            f.write("-"*30 + "\n\n")
            
            for file_name, contexts in results['path_contexts'].items():
                f.write(f"文件: {file_name}\n")
                f.write(f"可疑路径数: {len(contexts)}\n\n")
                
                for i, (path_id, context) in enumerate(contexts.items(), 1):
                    f.write(f"  {i}. {format_path_context_for_display(context, show_neighbors=False)}\n\n")
                
                f.write("-"*30 + "\n\n")
        
        saved_files['report'] = report_file
        
        logger.info(f"结果已保存到 {output_dir}")
        for file_type, file_path in saved_files.items():
            logger.info(f"  - {file_type}: {os.path.basename(file_path)}")
        
        return saved_files
    
    def get_contexts_for_llm(self, results: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """
        为LLM分析准备格式化的上下文数据
        
        Args:
            results: 分析结果
            
        Returns:
            {source_file: [formatted_context_dicts]}
        """
        llm_contexts = {}
        
        for file_name, contexts in results['path_contexts'].items():
            file_contexts = []
            
            for path_id, context in contexts.items():
                # 提取路径信息
                node_details = context.get('node_details', {})
                path_nodes = context.get('path_nodes', [])
                context_nodes = context.get('context_nodes', [])
                
                # 构建路径序列
                path_sequence = []
                for node_id in path_nodes:
                    if node_id in node_details:
                        method = node_details[node_id]['method']
                        path_sequence.append({
                            'node_id': node_id,
                            'method': method,
                            'depth': node_details[node_id]['depth'],
                            'is_suspicious': node_details[node_id]['is_suspicious']
                        })
                
                # 构建邻居节点信息
                neighbor_nodes = [nid for nid in context_nodes if nid not in path_nodes]
                neighbors_info = []
                for node_id in neighbor_nodes:
                    if node_id in node_details:
                        detail = node_details[node_id]
                        neighbors_info.append({
                            'node_id': node_id,
                            'method': detail['method'],
                            'depth': detail['depth'],
                            'fanout': detail['fanout'],
                            'is_suspicious': detail['is_suspicious'],
                            'related_paths': detail['related_paths']
                        })
                
                # 获取叶节点信息
                leaf_node_id = path_nodes[-1] if path_nodes else None
                leaf_info = node_details.get(leaf_node_id, {}).get('path_info', {}) if leaf_node_id else {}
                
                formatted_context = {
                    'path_id': path_id,
                    'tx_hash': context.get('tx_hash', 'unknown'),
                    'source_file': file_name,
                    'path_sequence': path_sequence,
                    'neighbors': neighbors_info,
                    'path_metadata': {
                        'label': leaf_info.get('label', 0),
                        'event_name': leaf_info.get('event_name', 'unknown'),
                        'attacker_address': leaf_info.get('attacker_address', 'unknown'),
                        'path_length': leaf_info.get('path_length', 0),
                        'contains_transfer': leaf_info.get('contains_transfer', False),
                        'contains_swap': leaf_info.get('contains_swap', False),
                        'total_value': leaf_info.get('total_value', 0)
                    },
                    'context_statistics': {
                        'total_nodes': len(context_nodes),
                        'path_nodes': len(path_nodes),
                        'neighbor_nodes': len(neighbor_nodes),
                        'edges': len(context.get('context_edges', []))
                    }
                }
                
                file_contexts.append(formatted_context)
            
            if file_contexts:
                llm_contexts[file_name] = file_contexts
        
        return llm_contexts


if __name__ == "__main__":
    # 测试主流程
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    input_dir = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled"
    output_dir = "/home/os/shuzheng/whole_pipeline/RQ3/results"
    
    try:
        # 创建分析器
        analyzer = ContextualPathAnalyzer(
            k_paths=30,
            k_neighbors=3
        )
        
        # 执行分析
        results = analyzer.analyze_with_context(input_dir)
        
        # 保存结果
        saved_files = analyzer.save_results(results, output_dir)
        
        # 显示摘要
        summary = results['summary']
        print("\n" + "="*60)
        print("分析完成摘要")
        print("="*60)
        print(f"处理文件: {summary['files_processed']}")
        print(f"可疑路径总数: {summary['total_suspicious_paths']}")
        print(f"LR宏平均命中率: {summary['lr_performance']['macro_attack_hit_rate']:.3f}")
        print(f"平均上下文节点数: {summary['context_statistics']['avg_context_nodes']:.1f}")
        print(f"平均邻居数: {summary['context_statistics']['avg_neighbors']:.1f}")
        print(f"结果保存在: {output_dir}")
        
    except Exception as e:
        logger.error(f"分析失败: {e}")
        import traceback
        traceback.print_exc()