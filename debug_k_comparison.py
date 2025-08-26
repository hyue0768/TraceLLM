#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
debug_k_comparison.py - 调试K值对比的token数量差异

验证不同K值是否真的产生不同的上下文大小和token数量
"""

import os
import sys
import logging
from datetime import datetime
from k_value_comparison import KValueComparisonAnalyzer
from llm_analyzer import LLMAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def debug_k_value_differences():
    """调试不同K值的差异"""
    
    input_dir = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled"
    
    try:
        logger.info("🔍 开始调试K值差异...")
        
        # 1. 创建分析器并获取原始上下文
        analyzer = KValueComparisonAnalyzer(k_paths=5, k_range=[0, 1, 2, 3])  # 减少数据量
        
        # 2. 使用最大K值获取初始上下文
        from contextual_path_analyzer import ContextualPathAnalyzer
        path_analyzer = ContextualPathAnalyzer(k_paths=5, k_neighbors=3)
        results = path_analyzer.analyze_with_context(input_dir)
        
        if not results['path_contexts']:
            logger.error("❌ 没有提取到路径上下文")
            return
        
        # 选择第一个事件进行详细分析
        first_event = list(results['path_contexts'].keys())[0]
        event_contexts = results['path_contexts'][first_event]
        
        logger.info(f"✅ 选择事件: {first_event}")
        logger.info(f"   原始路径数量: {len(event_contexts)}")
        
        # 3. 分析不同K值的上下文差异
        llm_analyzer = LLMAnalyzer()
        k_values = [0, 1, 2, 3]
        
        for k in k_values:
            logger.info(f"\n--- 分析K={k} ---")
            
            # 准备K值对应的上下文
            k_contexts = analyzer._prepare_contexts_for_k(event_contexts, k)
            
            # 统计邻居节点数量
            total_neighbors = 0
            total_context_nodes = 0
            
            for path_id, context in k_contexts.items():
                neighbors_count = len(context.get('neighbors', []))
                context_nodes_count = len(context.get('context_nodes', []))
                total_neighbors += neighbors_count
                total_context_nodes += context_nodes_count
                
                logger.debug(f"  路径 {path_id}: 邻居={neighbors_count}, 上下文节点={context_nodes_count}")
            
            logger.info(f"  总邻居节点数: {total_neighbors}")
            logger.info(f"  总上下文节点数: {total_context_nodes}")
            
            # 构建prompt并计算长度
            first_context = list(k_contexts.values())[0]
            event_name = first_context.get('path_metadata', {}).get('event_name', 'Test Event')
            
            prompt = llm_analyzer.build_attacker_victim_prompt(
                list(k_contexts.values()), event_name, k
            )
            
            logger.info(f"  Prompt长度: {len(prompt):,} 字符")
            logger.info(f"  估计Token数: {len(prompt) // 4:,}")  # 粗略估计：4个字符=1个token
            
            # 显示prompt的前200字符和后200字符以验证内容差异
            logger.debug(f"  Prompt开头: {prompt[:200]}...")
            logger.debug(f"  Prompt结尾: ...{prompt[-200:]}")
        
        logger.info("\n✅ K值差异调试完成")
        
    except Exception as e:
        logger.error(f"❌ 调试失败: {str(e)}")
        import traceback
        traceback.print_exc()


def detailed_context_analysis():
    """详细分析上下文结构"""
    
    input_dir = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled"
    
    try:
        # 获取一个事件的上下文
        from contextual_path_analyzer import ContextualPathAnalyzer
        path_analyzer = ContextualPathAnalyzer(k_paths=3, k_neighbors=3)
        results = path_analyzer.analyze_with_context(input_dir)
        
        first_event = list(results['path_contexts'].keys())[0]
        event_contexts = results['path_contexts'][first_event]
        
        # 分析第一个路径的上下文结构
        first_path_id = list(event_contexts.keys())[0]
        first_context = event_contexts[first_path_id]
        
        logger.info("📊 详细上下文结构分析:")
        logger.info(f"事件: {first_event}")
        logger.info(f"路径ID: {first_path_id}")
        
        # 路径节点
        path_nodes = first_context.get('path_nodes', [])
        logger.info(f"路径节点数: {len(path_nodes)}")
        
        # 邻居节点
        neighbors = first_context.get('neighbors', [])
        logger.info(f"邻居节点数: {len(neighbors)}")
        
        # 节点详情
        node_details = first_context.get('node_details', {})
        logger.info(f"节点详情数: {len(node_details)}")
        
        # 显示前几个邻居节点的信息
        logger.info("前5个邻居节点:")
        for i, neighbor in enumerate(neighbors[:5]):
            method = neighbor.get('method', 'unknown')
            depth = neighbor.get('depth', 0)
            fanout = neighbor.get('fanout', 0)
            logger.info(f"  {i+1}. {method} (深度:{depth}, 出度:{fanout})")
        
        # 测试不同K值的效果
        analyzer = KValueComparisonAnalyzer(k_paths=3, k_range=[0, 1, 2, 3])
        
        logger.info("\n🔍 测试不同K值的邻居筛选效果:")
        for k in [0, 1, 2, 3]:
            k_contexts = analyzer._prepare_contexts_for_k({first_path_id: first_context}, k)
            k_context = k_contexts[first_path_id]
            k_neighbors = k_context.get('neighbors', [])
            
            logger.info(f"K={k}: 邻居数={len(k_neighbors)}")
            
            # 显示邻居的深度分布
            if k_neighbors:
                depths = [n.get('depth', 0) for n in k_neighbors]
                logger.info(f"  邻居深度范围: {min(depths)} - {max(depths)}")
            
    except Exception as e:
        logger.error(f"❌ 详细分析失败: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("选择调试模式:")
    print("1. K值差异调试")
    print("2. 详细上下文结构分析")
    
    choice = input("请输入选择 (1-2): ").strip()
    
    if choice == "1":
        debug_k_value_differences()
    elif choice == "2":
        detailed_context_analysis()
    else:
        logger.info("运行默认调试...")
        debug_k_value_differences()