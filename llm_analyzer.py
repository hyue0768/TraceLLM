#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_analyzer.py - LLM分析模块

基于路径上下文识别attacker/victim地址，支持不同K值的对比分析
参考analyze_user_behavior.py的LLM调用逻辑
"""

import os
import sys
import json
import time
import requests
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import logging

# 添加上级目录到路径
sys.path.append('/home/os/shuzheng/whole_pipeline/src')
from config.settings import Settings

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """LLM分析器，用于识别攻击者和受害者地址"""
    
    def __init__(self):
        """初始化LLM分析器"""
        self.settings = Settings()
        
        # 获取LLM配置
        self.api_key = self.settings.APIKEY
        self.base_url = self.settings.BASEURL
        self.model_name = self.settings.MODELNAME
        
        if not self.api_key or not self.base_url or not self.model_name:
            raise ValueError("LLM配置不完整，请检查环境变量 APIKEY, BASEURL, MODELNAME")
        
        # 确保base_url格式正确
        if not self.base_url.endswith('/'):
            self.base_url += '/'
        if not self.base_url.endswith('v1/'):
            self.base_url += 'v1/'
        
        logger.info(f"LLM分析器初始化完成")
        logger.info(f"  - 模型: {self.model_name}")
        logger.info(f"  - 端点: {self.base_url}")
    
    def build_attacker_victim_prompt(self, contexts: List[Dict[str, Any]], 
                                   event_name: str, k_neighbors: int) -> str:
        """
        构建用于识别攻击者和受害者地址的prompt
        
        Args:
            contexts: 路径扩展上下文列表（新格式）
            event_name: 事件名称
            k_neighbors: 路径扩展层数
            
        Returns:
            格式化的prompt字符串
        """
        prompt_parts = []
        
        # 1. 任务描述
        prompt_parts.append("""你是一个区块链安全分析专家。我将为你提供一个安全事件中筛选出的Top-30可疑执行路径及其K层路径扩展上下文。

⚠️ 重要：这些路径都是通过机器学习模型识别的高度可疑路径，不是普通的正常路径！

你的任务是分析这些可疑路径和它们的扩展上下文，识别出：
1. ATTACKER ADDRESS - 攻击者地址（发起恶意操作的地址）
2. VICTIM ADDRESS - 受害者地址（被攻击的地址或协议）

分析要点：
- 这些路径已经被标记为异常/可疑，重点分析攻击模式
- 关注资金流向和价值转移
- 识别恶意方法调用模式
- 分析合约创建和部署行为
- 追踪异常的函数调用链

""")
        
        # 2. 事件基本信息
        prompt_parts.append(f"=== 安全事件信息 ===\n")
        prompt_parts.append(f"事件名称: {event_name}\n")
        prompt_parts.append(f"路径扩展层数: K={k_neighbors}\n")
        prompt_parts.append(f"可疑路径数量: {len(contexts)}\n")
        if k_neighbors > 0:
            prompt_parts.append(f"说明: K={k_neighbors}表示为每条可疑路径扩展了{k_neighbors}层相关执行路径\n")
        else:
            prompt_parts.append(f"说明: K=0表示仅分析可疑路径本身，不包含扩展路径\n")
        prompt_parts.append("\n")
        
        # 3. 每个可疑路径及其扩展的详细信息
        all_addresses = set()
        for i, context in enumerate(contexts, 1):
            prompt_parts.append(f"=== 可疑路径 {i} (已筛选) ===\n")
            
            # 基本信息
            target_path_id = context.get('target_path_id', context.get('path_id', 'unknown'))
            prompt_parts.append(f"目标路径ID: {target_path_id}\n")
            prompt_parts.append(f"交易Hash: {context.get('tx_hash', 'unknown')}\n")
            prompt_parts.append(f"源文件: {context.get('source_file', 'unknown')}\n")
            
            # 路径扩展统计信息
            layer_stats = context.get('layer_statistics', {})
            prompt_parts.append(f"路径扩展信息:\n")
            prompt_parts.append(f"  - 扩展层数: K={layer_stats.get('expansion_layers', k_neighbors)}\n")
            prompt_parts.append(f"  - 相关路径总数: {layer_stats.get('total_paths', 1)}\n")
            prompt_parts.append(f"  - 涉及节点总数: {layer_stats.get('total_nodes', 0)}\n")
            prompt_parts.append(f"  - 目标路径长度: {layer_stats.get('target_path_length', 0)}\n")
            
            # 显示所有相关路径
            related_paths = context.get('related_paths', {})
            path_details = context.get('path_details', {})
            
            if related_paths:
                prompt_parts.append(f"\n相关执行路径 (共{len(related_paths)}条):\n")
                
                for j, (path_id, node_ids) in enumerate(related_paths.items(), 1):
                    path_detail = path_details.get(path_id, {})
                    is_target = path_detail.get('is_target', False)
                    methods = path_detail.get('methods', [])
                    
                    path_type = "🎯目标可疑路径" if is_target else f"🔗扩展路径"
                    prompt_parts.append(f"  {j}. {path_type} (ID: {path_id}):\n")
                    
                    if methods:
                        path_sequence = " → ".join(methods)
                        prompt_parts.append(f"     执行序列: {path_sequence}\n")
                    else:
                        prompt_parts.append(f"     节点序列: {' → '.join(map(str, node_ids))}\n")
            
            # 显示节点详细信息（包括路径节点和扩展节点）
            node_details = context.get('node_details', {})
            if node_details:
                target_nodes = related_paths.get(target_path_id, [])
                expansion_nodes = []
                for pid, nodes in related_paths.items():
                    if pid != target_path_id:
                        expansion_nodes.extend(nodes)
                
                prompt_parts.append(f"\n🎯目标路径节点详情:\n")
                for node_id in target_nodes[:10]:  # 限制显示数量
                    if node_id in node_details:
                        detail = node_details[node_id]
                        method = detail.get('method', 'unknown')
                        depth = detail.get('depth', 0)
                        is_suspicious = detail.get('is_suspicious', False)
                        
                        sus_mark = " [🚨标记可疑]" if is_suspicious else ""
                        prompt_parts.append(f"  - {method} (深度:{depth}){sus_mark}\n")
                
                if k_neighbors > 0 and expansion_nodes:
                    prompt_parts.append(f"\n🔗扩展路径节点 (K={k_neighbors}层, 共{len(expansion_nodes)}个):\n")
                    unique_expansion_nodes = list(set(expansion_nodes))[:15]  # 限制显示数量
                    for node_id in unique_expansion_nodes:
                        if node_id in node_details:
                            detail = node_details[node_id]
                            method = detail.get('method', 'unknown')
                            depth = detail.get('depth', 0)
                            is_suspicious = detail.get('is_suspicious', False)
                            
                            sus_mark = " [🚨标记可疑]" if is_suspicious else ""
                            prompt_parts.append(f"  - {method} (深度:{depth}){sus_mark}\n")
                    
                    if len(expansion_nodes) > 15:
                        prompt_parts.append(f"  ... 还有 {len(expansion_nodes) - 15} 个扩展节点\n")
            
            prompt_parts.append("\n" + "-" * 60 + "\n\n")
        
        # 4. 分析要求
        prompt_parts.append("""=== 分析要求 ===
⚠️ 重要提醒：以上所有路径都是通过机器学习模型从大量交易中筛选出的Top-30高度可疑路径！

请基于这些已筛选的可疑路径分析，识别：

1. ATTACKER ADDRESS（攻击者地址）:
   - 从可疑路径中识别攻击发起者
   - 分析恶意操作的源头地址
   - 追踪资金或权限的非法获取者
   - 识别异常行为模式的主导者

2. VICTIM ADDRESS（受害者地址）:
   - 从可疑路径中识别受害目标
   - 分析资金或权限的损失者
   - 识别被利用的协议或用户地址
   - 确定攻击的受害对象

分析策略：
- 这些路径已被标记为可疑，重点分析攻击逻辑
- 关注路径间的连接关系和扩展模式
- 结合多条路径的证据进行综合判断
- 通过K层扩展路径了解完整攻击链条

请用以下JSON格式回答：
```json
{
  "analysis": {
    "summary": "基于可疑路径的攻击过程分析",
    "attack_pattern": "识别的攻击模式和手法",
    "suspicious_indicators": "主要的可疑行为指标"
  },
  "attacker_address": "0x...",
  "victim_address": "0x...",
  "confidence": {
    "attacker": "HIGH/MEDIUM/LOW",
    "victim": "HIGH/MEDIUM/LOW"
  },
  "reasoning": {
    "attacker": "基于可疑路径识别攻击者的详细理由",
    "victim": "基于可疑路径识别受害者的详细理由"
  },
  "path_evidence": {
    "key_suspicious_paths": "关键的可疑路径ID列表",
    "attack_flow": "从路径看到的攻击流程"
  }
}
```

注意：
- 所有分析都基于已筛选的可疑路径
- 置信度应基于多路径证据的一致性
- 重点关注路径扩展带来的上下文信息
""")
        
        return "".join(prompt_parts)
    
    def call_llm(self, prompt: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        调用LLM API
        
        Args:
            prompt: 输入prompt
            max_retries: 最大重试次数
            
        Returns:
            包含响应和token使用信息的字典
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "你是一个专业的区块链安全分析专家，擅长分析智能合约攻击和识别恶意地址。我给你提供的trace信息都是经过去重处理的一笔攻击交易中的Top 30的可疑路径，请基于这些信息进行分析。"
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # 降低温度以获得更一致的结果
            "max_tokens": 4000
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}chat/completions",
                    headers=headers,
                    json=data,
                    timeout=300  # 5分钟超时
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # 提取响应内容和token使用情况
                    content = result['choices'][0]['message']['content']
                    usage = result.get('usage', {})
                    
                    return {
                        'success': True,
                        'content': content,
                        'prompt_tokens': usage.get('prompt_tokens', 0),
                        'completion_tokens': usage.get('completion_tokens', 0),
                        'total_tokens': usage.get('total_tokens', 0),
                        'model': self.model_name,
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    logger.warning(f"LLM API调用失败 (尝试 {attempt+1}/{max_retries}): "
                                 f"状态码 {response.status_code}, 响应: {response.text}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"LLM API调用超时 (尝试 {attempt+1}/{max_retries})")
                
            except Exception as e:
                logger.warning(f"LLM API调用异常 (尝试 {attempt+1}/{max_retries}): {str(e)}")
            
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # 指数退避
        
        return {
            'success': False,
            'error': 'LLM API调用失败，已达到最大重试次数',
            'prompt_tokens': 0,
            'completion_tokens': 0,
            'total_tokens': 0
        }
    
    def parse_llm_response(self, response_content: str) -> Dict[str, Any]:
        """
        解析LLM响应，提取JSON结果
        
        Args:
            response_content: LLM返回的原始内容
            
        Returns:
            解析后的结构化结果
        """
        try:
            # 尝试提取JSON部分
            start_idx = response_content.find('{')
            end_idx = response_content.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_str = response_content[start_idx:end_idx+1]
                parsed = json.loads(json_str)
                
                # 验证必要字段
                required_fields = ['attacker_address', 'victim_address']
                for field in required_fields:
                    if field not in parsed:
                        parsed[field] = "UNKNOWN"
                
                return {
                    'success': True,
                    'parsed_result': parsed,
                    'raw_response': response_content
                }
            else:
                # 无法找到JSON，尝试简单解析
                return {
                    'success': False,
                    'error': 'No valid JSON found in response',
                    'raw_response': response_content,
                    'parsed_result': {
                        'attacker_address': 'UNKNOWN',
                        'victim_address': 'UNKNOWN',
                        'analysis': {'summary': response_content[:200] + '...'}
                    }
                }
                
        except json.JSONDecodeError as e:
            logger.warning(f"JSON解析失败: {str(e)}")
            return {
                'success': False,
                'error': f'JSON parsing failed: {str(e)}',
                'raw_response': response_content,
                'parsed_result': {
                    'attacker_address': 'UNKNOWN',
                    'victim_address': 'UNKNOWN',
                    'analysis': {'summary': response_content[:200] + '...'}
                }
            }
    
    def analyze_event_contexts(self, event_contexts: Dict[str, Any], 
                             k_neighbors: int) -> Dict[str, Any]:
        """
        分析单个事件的所有路径扩展上下文
        
        Args:
            event_contexts: 事件的路径扩展上下文数据（新格式）
            k_neighbors: 路径扩展层数
            
        Returns:
            分析结果
        """
        if not event_contexts:
            return {
                'success': False,
                'error': 'No contexts provided',
                'k_neighbors': k_neighbors
            }
        
        # 获取事件信息（从新格式中提取）
        first_context = list(event_contexts.values())[0]
        
        # 尝试从多个可能的位置获取事件名称
        event_name = 'Unknown Event'
        if 'source_file' in first_context:
            # 从文件名中提取事件名称
            source_file = first_context['source_file']
            if 'event_' in source_file:
                parts = source_file.split('_')
                if len(parts) >= 3:
                    event_name = '_'.join(parts[1:4])  # event_2_Barley_Finance 格式
        
        # 从node_details中查找path_info
        node_details = first_context.get('node_details', {})
        for node_id, detail in node_details.items():
            path_info = detail.get('path_info')
            if path_info and isinstance(path_info, dict):
                if 'event_name' in path_info:
                    event_name = path_info['event_name']
                    break
        
        logger.info(f"分析事件: {event_name}, K={k_neighbors}, 可疑路径数: {len(event_contexts)}")
        
        # 构建prompt
        contexts_list = list(event_contexts.values())
        prompt = self.build_attacker_victim_prompt(contexts_list, event_name, k_neighbors)
        
        # 调用LLM
        llm_result = self.call_llm(prompt)
        
        if not llm_result['success']:
            return {
                'success': False,
                'error': llm_result.get('error', 'LLM call failed'),
                'k_neighbors': k_neighbors,
                'event_name': event_name,
                'prompt_length': len(prompt),
                'token_usage': {
                    'prompt_tokens': 0,
                    'completion_tokens': 0,
                    'total_tokens': 0
                }
            }
        
        # 解析响应
        parsed_result = self.parse_llm_response(llm_result['content'])
        
        # 整合结果
        result = {
            'success': True,
            'event_name': event_name,
            'k_neighbors': k_neighbors,
            'num_paths': len(event_contexts),
            'prompt_length': len(prompt),
            'token_usage': {
                'prompt_tokens': llm_result['prompt_tokens'],
                'completion_tokens': llm_result['completion_tokens'],
                'total_tokens': llm_result['total_tokens']
            },
            'llm_response': {
                'raw_content': llm_result['content'],
                'parsing_success': parsed_result['success'],
                'parsed_data': parsed_result['parsed_result']
            },
            'identified_addresses': {
                'attacker': parsed_result['parsed_result'].get('attacker_address', 'UNKNOWN'),
                'victim': parsed_result['parsed_result'].get('victim_address', 'UNKNOWN')
            },
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"✅ 事件 {event_name} 分析完成")
        logger.info(f"  - Token使用: {result['token_usage']['total_tokens']}")
        logger.info(f"  - 攻击者: {result['identified_addresses']['attacker']}")
        logger.info(f"  - 受害者: {result['identified_addresses']['victim']}")
        
        return result


if __name__ == "__main__":
    # 简单测试
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        analyzer = LLMAnalyzer()
        print(f"LLM分析器初始化成功")
        print(f"模型: {analyzer.model_name}")
        print(f"端点: {analyzer.base_url}")
        
    except Exception as e:
        print(f"初始化失败: {e}")
        import traceback
        traceback.print_exc()