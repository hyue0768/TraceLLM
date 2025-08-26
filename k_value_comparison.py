#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
k_value_comparison.py - K值对比分析脚本

对每个事件，使用K=0到5的不同邻域大小进行LLM分析，
比较token消耗和地址识别准确性的变化
"""

import os
import json
import pandas as pd
from typing import Dict, List, Any
from datetime import datetime
import logging

from contextual_path_analyzer import ContextualPathAnalyzer
from llm_analyzer import LLMAnalyzer

logger = logging.getLogger(__name__)


class KValueComparisonAnalyzer:
    """K值对比分析器"""
    
    def __init__(self, k_paths: int = 30, k_range: List[int] = None):
        """
        初始化分析器
        
        Args:
            k_paths: 选择的top路径数量
            k_range: K值范围，默认[0,1,2,3,4,5]
        """
        self.k_paths = k_paths
        self.k_range = k_range or [0, 1, 2, 3, 4, 5]
        
        # 初始化LLM分析器
        self.llm_analyzer = LLMAnalyzer()
        
        logger.info(f"K值对比分析器初始化完成")
        logger.info(f"  - Top-K路径: {k_paths}")
        logger.info(f"  - K值范围: {self.k_range}")
    

    

    
    def run_full_comparison(self, input_dir: str, output_dir: str) -> Dict[str, Any]:
        """
        运行完整的K值对比分析
        
        Args:
            input_dir: 输入目录
            output_dir: 输出目录
            
        Returns:
            完整的分析结果
        """
        logger.info("="*80)
        logger.info("开始K值对比分析")
        logger.info("="*80)
        
        # 为每个K值都进行独立的路径提取和上下文构建
        all_k_path_results = {}
        
        for k in self.k_range:
            logger.info(f"为K={k}构建独立的路径上下文...")
            
            path_analyzer = ContextualPathAnalyzer(
                k_paths=self.k_paths,
                k_neighbors=k
            )
            
            # 获取K值对应的路径上下文
            k_path_results = path_analyzer.analyze_with_context(input_dir)
            all_k_path_results[k] = k_path_results
            
            if k_path_results['path_contexts']:
                total_contexts = sum(len(contexts) for contexts in k_path_results['path_contexts'].values())
                logger.info(f"  K={k}: 提取到 {total_contexts} 个路径上下文")
            else:
                logger.warning(f"  K={k}: 未提取到路径上下文")
        
        logger.info(f"✅ 所有K值路径提取完成")
        
        # 使用K=0的结果作为基础事件列表（因为所有K值的事件应该是相同的）
        base_events = list(all_k_path_results[0]['path_contexts'].keys()) if 0 in all_k_path_results else []
        
        # 为每个事件进行K值对比分析
        event_results = {}
        total_tokens_by_k = {k: 0 for k in self.k_range}
        
        for event_name in base_events:
            logger.info(f"\n📊 处理事件: {event_name}")
            
            # 为当前事件收集所有K值的上下文
            event_k_contexts = {}
            for k in self.k_range:
                if k in all_k_path_results and event_name in all_k_path_results[k]['path_contexts']:
                    event_k_contexts[k] = all_k_path_results[k]['path_contexts'][event_name]
                else:
                    logger.warning(f"事件 {event_name} 在K={k}时没有上下文数据")
                    event_k_contexts[k] = {}
            
            # 分析所有K值
            k_results = {}
            for k in self.k_range:
                if event_k_contexts[k]:
                    logger.info(f"  分析K={k}...")
                    try:
                        analysis_result = self.llm_analyzer.analyze_event_contexts(event_k_contexts[k], k)
                        k_results[k] = analysis_result
                        
                        if analysis_result['success']:
                            tokens = analysis_result['token_usage']['total_tokens']
                            attacker = analysis_result['identified_addresses']['attacker']
                            victim = analysis_result['identified_addresses']['victim']
                            logger.info(f"    ✅ K={k}: Tokens={tokens}, 攻击者={attacker[:10]}..., 受害者={victim[:10]}...")
                            total_tokens_by_k[k] += tokens
                        else:
                            logger.error(f"    ❌ K={k}: {analysis_result.get('error', 'Unknown error')}")
                    except Exception as e:
                        logger.error(f"    ❌ K={k} 分析失败: {str(e)}")
                        k_results[k] = {
                            'success': False,
                            'error': str(e),
                            'k_neighbors': k,
                            'event_name': event_name
                        }
                else:
                    logger.warning(f"  跳过K={k}（无上下文数据）")
                    k_results[k] = {
                        'success': False,
                        'error': 'No context data',
                        'k_neighbors': k,
                        'event_name': event_name
                    }
            
            event_results[event_name] = k_results
        
        # 整理最终结果
        final_results = {
            'analysis_config': {
                'k_paths': self.k_paths,
                'k_range': self.k_range,
                'input_dir': input_dir,
                'timestamp': datetime.now().isoformat()
            },
            'all_k_path_results': all_k_path_results,  # 包含所有K值的路径提取结果
            'event_analysis_results': event_results,
            'global_statistics': {
                'total_events': len(event_results),
                'successful_events_by_k': {},
                'total_tokens_by_k': total_tokens_by_k,
                'avg_tokens_by_k': {}
            }
        }
        
        # 计算全局统计
        for k in self.k_range:
            successful_count = sum(
                1 for event_results in event_results.values()
                if k in event_results and event_results[k].get('success', False)
            )
            final_results['global_statistics']['successful_events_by_k'][k] = successful_count
            
            if successful_count > 0:
                avg_tokens = total_tokens_by_k[k] / successful_count
                final_results['global_statistics']['avg_tokens_by_k'][k] = avg_tokens
            else:
                final_results['global_statistics']['avg_tokens_by_k'][k] = 0
        
        # 保存结果
        saved_files = self._save_comparison_results(final_results, output_dir)
        
        # 为每个事件保存独立的LLM分析报告
        self._save_individual_event_reports(final_results, output_dir)
        
        # 输出摘要
        self._print_comparison_summary(final_results)
        
        logger.info(f"\n📁 结果已保存到: {output_dir}")
        for file_type, file_path in saved_files.items():
            logger.info(f"  - {file_type}: {os.path.basename(file_path)}")
        
        return final_results
    
    def _save_comparison_results(self, results: Dict[str, Any], output_dir: str) -> Dict[str, str]:
        """保存对比分析结果"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_files = {}
        
        # 1. 保存完整结果
        full_file = os.path.join(output_dir, f"k_value_comparison_full_{timestamp}.json")
        with open(full_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        saved_files['full_results'] = full_file
        
        # 2. 保存事件级汇总
        event_summary = []
        for event_name, k_results in results['event_analysis_results'].items():
            for k, result in k_results.items():
                if result.get('success', False):
                    event_summary.append({
                        'event_name': event_name,
                        'k_neighbors': k,
                        'total_tokens': result['token_usage']['total_tokens'],
                        'prompt_tokens': result['token_usage']['prompt_tokens'],
                        'completion_tokens': result['token_usage']['completion_tokens'],
                        'attacker_address': result['identified_addresses']['attacker'],
                        'victim_address': result['identified_addresses']['victim'],
                        'num_paths': result['num_paths'],
                        'prompt_length': result['prompt_length']
                    })
        
        if event_summary:
            summary_df = pd.DataFrame(event_summary)
            summary_file = os.path.join(output_dir, f"k_value_event_summary_{timestamp}.csv")
            summary_df.to_csv(summary_file, index=False)
            saved_files['event_summary'] = summary_file
        
        # 3. 保存K值统计汇总
        k_stats = []
        for k in results['analysis_config']['k_range']:
            stats = results['global_statistics']
            k_stats.append({
                'k_neighbors': k,
                'successful_events': stats['successful_events_by_k'][k],
                'total_tokens': stats['total_tokens_by_k'][k],
                'avg_tokens_per_event': stats['avg_tokens_by_k'][k],
                'total_events': stats['total_events']
            })
        
        k_stats_df = pd.DataFrame(k_stats)
        k_stats_file = os.path.join(output_dir, f"k_value_statistics_{timestamp}.csv")
        k_stats_df.to_csv(k_stats_file, index=False)
        saved_files['k_statistics'] = k_stats_file
        
        # 4. 保存地址识别结果对比
        address_comparison = []
        for event_name, k_results in results['event_analysis_results'].items():
            event_data = {'event_name': event_name}
            
            for k in results['analysis_config']['k_range']:
                if k in k_results and k_results[k].get('success', False):
                    result = k_results[k]
                    event_data[f'attacker_k{k}'] = result['identified_addresses']['attacker']
                    event_data[f'victim_k{k}'] = result['identified_addresses']['victim']
                    event_data[f'tokens_k{k}'] = result['token_usage']['total_tokens']
                else:
                    event_data[f'attacker_k{k}'] = 'FAILED'
                    event_data[f'victim_k{k}'] = 'FAILED'
                    event_data[f'tokens_k{k}'] = 0
            
            address_comparison.append(event_data)
        
        if address_comparison:
            addr_df = pd.DataFrame(address_comparison)
            addr_file = os.path.join(output_dir, f"address_identification_comparison_{timestamp}.csv")
            addr_df.to_csv(addr_file, index=False)
            saved_files['address_comparison'] = addr_file
        
        return saved_files
    
    def _save_individual_event_reports(self, results: Dict[str, Any], output_dir: str):
        """为每个事件保存独立的LLM分析报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = os.path.join(output_dir, "individual_event_reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        for event_name, k_results in results['event_analysis_results'].items():
            # 清理事件名称作为文件名
            safe_event_name = "".join(c for c in event_name if c.isalnum() or c in ('_', '-')).strip()
            safe_event_name = safe_event_name[:50]  # 限制长度
            
            # 为每个事件创建报告
            event_report = {
                'event_name': event_name,
                'analysis_timestamp': timestamp,
                'k_value_results': {}
            }
            
            # 整理每个K值的结果
            for k, result in k_results.items():
                if result.get('success', False):
                    event_report['k_value_results'][f'k_{k}'] = {
                        'k_neighbors': k,
                        'token_usage': result['token_usage'],
                        'identified_addresses': result['identified_addresses'],
                        'llm_analysis': {
                            'raw_response': result['llm_response']['raw_content'],
                            'parsed_data': result['llm_response']['parsed_data']
                        },
                        'prompt_length': result['prompt_length'],
                        'num_paths': result['num_paths']
                    }
                else:
                    event_report['k_value_results'][f'k_{k}'] = {
                        'k_neighbors': k,
                        'error': result.get('error', 'Unknown error'),
                        'success': False
                    }
            
            # 保存JSON格式的详细报告
            json_file = os.path.join(reports_dir, f"{safe_event_name}_{timestamp}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(event_report, f, indent=2, ensure_ascii=False, default=str)
            
            # 保存可读文本格式的报告
            txt_file = os.path.join(reports_dir, f"{safe_event_name}_{timestamp}.txt")
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"事件分析报告: {event_name}\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"分析时间: {timestamp}\n")
                f.write(f"K值范围: {list(k_results.keys())}\n\n")
                
                for k in sorted(k_results.keys()):
                    result = k_results[k]
                    f.write(f"--- K={k} 分析结果 ---\n")
                    
                    if result.get('success', False):
                        tokens = result['token_usage']
                        addresses = result['identified_addresses']
                        
                        f.write(f"状态: ✅ 成功\n")
                        f.write(f"Token使用: {tokens['total_tokens']} (输入:{tokens['prompt_tokens']}, 输出:{tokens['completion_tokens']})\n")
                        f.write(f"攻击者地址: {addresses['attacker']}\n")
                        f.write(f"受害者地址: {addresses['victim']}\n")
                        f.write(f"路径数量: {result['num_paths']}\n")
                        f.write(f"Prompt长度: {result['prompt_length']} 字符\n\n")
                        
                        # 添加LLM分析内容（截取前500字符）
                        llm_content = result['llm_response']['raw_content']
                        f.write(f"LLM分析内容（前500字符）:\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"{llm_content[:500]}...\n")
                        f.write("-" * 40 + "\n\n")
                    else:
                        f.write(f"状态: ❌ 失败\n")
                        f.write(f"错误: {result.get('error', 'Unknown error')}\n\n")
        
        logger.info(f"✅ 已为 {len(results['event_analysis_results'])} 个事件保存独立报告到: {reports_dir}")
    
    def _print_comparison_summary(self, results: Dict[str, Any]):
        """打印对比分析摘要"""
        logger.info("\n" + "="*80)
        logger.info("K值对比分析摘要")
        logger.info("="*80)
        
        stats = results['global_statistics']
        total_events = stats['total_events']
        
        logger.info(f"总事件数: {total_events}")
        logger.info(f"K值范围: {results['analysis_config']['k_range']}")
        
        logger.info(f"\n📊 各K值统计:")
        for k in results['analysis_config']['k_range']:
            successful = stats['successful_events_by_k'][k]
            total_tokens = stats['total_tokens_by_k'][k]
            avg_tokens = stats['avg_tokens_by_k'][k]
            
            logger.info(f"  K={k}: 成功={successful}/{total_events}, "
                       f"总Tokens={total_tokens:,}, 平均Tokens={avg_tokens:.1f}")
        
        logger.info(f"\n📋 分析完成统计:")
        logger.info(f"  成功分析的事件数: {max(stats['successful_events_by_k'].values())}/{total_events}")
        logger.info(f"  总Token消耗: {sum(stats['total_tokens_by_k'].values()):,}")
        
        # 显示每个事件的K值分析结果
        logger.info(f"\n📊 各事件K值分析结果:")
        for event_name, k_results in results['event_analysis_results'].items():
            successful_k_values = [k for k, result in k_results.items() if result.get('success', False)]
            if successful_k_values:
                logger.info(f"  {event_name}: 成功分析K值 {successful_k_values}")
            else:
                logger.info(f"  {event_name}: ❌ 所有K值分析均失败")


if __name__ == "__main__":
    # 运行K值对比分析
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    input_dir = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled"
    output_dir = "/home/os/shuzheng/whole_pipeline/RQ3/k_comparison_results"
    
    try:
        # 创建分析器
        analyzer = KValueComparisonAnalyzer(
            k_paths=30,
            k_range=[0, 1, 2, 3, 4, 5]
        )
        
        # 运行完整分析
        results = analyzer.run_full_comparison(input_dir, output_dir)
        
        print("\n🎉 K值对比分析完成!")
        
    except Exception as e:
        logger.error(f"❌ K值对比分析失败: {e}")
        import traceback
        traceback.print_exc()