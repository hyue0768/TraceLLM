from typing import Tuple, Dict, List, Optional
from src.first_LLM.rag_handler import RAG_INSTANCE 
import re
from openai import OpenAI
from config.settings import settings
import json
import os
from web3 import Web3
import traceback
import requests
import datetime  # 添加datetime模块用于日期处理

class LLMQueryProcessor:
    PROMPT_TEMPLATE = """As a blockchain security analysis expert, please extract from the user query:
1. Target contract address (a hexadecimal string starting with 0x)
2. Time/Block range:
   - Block numbers (start and end block numbers)
   - Specific date (YYYY-MM-DD format)
   - Date range (from YYYY-MM-DD to YYYY-MM-DD)
   - Relative time (e.g., "last 3 days")
3. Analysis focus, with emphasis on:
   - Security event/hack attack analysis
   - Contract interaction behavior analysis
   - Related contract code analysis
   - Fund flow tracking
4. Analysis type:
   - "security_analysis": Analyze contract interactions and related contract security issues
   - "contract_analysis": Analyze only a single contract code
   - "transaction_analysis": Analyze only transaction history

User input: {user_input}

Return the result strictly in the following JSON format, without any additional text:
{{
  "token_identifier": "Target contract address",
  "time_range_hint": "Specific time/date range (including YYYY-MM-DD format if present)",
  "analysis_focus": ["Security event analysis", "Interaction behavior analysis", "Code analysis", "Fund flow"],
  "analysis_type": "security_analysis/contract_analysis/transaction_analysis"
}}"""
    APIKEY = settings.APIKEY
    BASEURL = settings.BASEURL
    MODELNAME = settings.MODELNAME
    client = OpenAI(
        base_url = BASEURL,
        api_key = APIKEY,
    )

    def parse_query(self, user_input: str) -> Tuple[Dict, Dict]:
        """Return (LLM parsing result, RAG data)"""
        # Get current block (at the start of the function to avoid repeated calls)
        try:
            # 获取alchemy URL
            alchemy_url = os.getenv("ALCHEMY_URL")
            if not alchemy_url:
                alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
                if alchemy_api_key:
                    alchemy_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
                else:
                    # 尝试从网络配置获取
                    try:
                        network_config = settings.NETWORKS["ethereum"]
                        alchemy_url = network_config.get('rpc_url')
                    except Exception:
                        alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/demo"  # 默认值
            
            w3 = Web3(Web3.HTTPProvider(alchemy_url))
            current_block = w3.eth.block_number
            print(f"当前区块高度: {current_block}")
        except Exception as e:
            print(f"获取当前区块失败: {str(e)}")
            # 使用一个保守的默认值
            current_block = 19000000  # 设置一个合理的近期区块号作为默认值
            print(f"使用默认当前区块高度: {current_block}")
        
        # Initialize variables
        start_block = None
        end_block = None
        time_range_hint = None
        network = "ethereum"  # Fixed to Ethereum network
        
        # Check if it's an Ethereum address format
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        address_match = address_pattern.search(user_input)
        
        # Check if block range is specified
        block_pattern = re.compile(
            r'block\s*'          # "block" prefix
            r'(\d+)'            # Capture start block number (group 1)
            r'\s*'              # Allow spaces
            r'(?:'              # Non-capturing group start
            r'[to\-~]+\s*'    # Match any separator (to/-/~ etc.)
            r'(?:block\s*)?'     # Allow optional "block" keyword
            r')'                # Non-capturing group end
            r'(\d+)'            # Capture end block number (group 2)
        )
        block_match = block_pattern.search(user_input)
        
        # Check if time range is specified (e.g., "last hour")
        time_pattern = re.compile(
            r'last\s+'           # "last" prefix
            r'(\d*\s*)?'         # Optional number
            r'(hour|minute|day|week|month)s?'  # Time unit
        )
        time_match = time_pattern.search(user_input)
        
        # 新增：检查是否指定了具体日期 (YYYY-MM-DD)
        date_pattern = re.compile(
            r'(\d{4})-(\d{1,2})-(\d{1,2})'  # 匹配 YYYY-MM-DD 格式
        )
        date_match = date_pattern.search(user_input)
        
        # 如果指定了日期范围 (两个日期，用"to"或"-"连接)
        date_range_pattern = re.compile(
            r'(\d{4})-(\d{1,2})-(\d{1,2})'  # 第一个日期
            r'\s*(?:to|[-~])\s*'              # 分隔符（支持"to"、"-"或"~"）
            r'(\d{4})-(\d{1,2})-(\d{1,2})'  # 第二个日期
        )
        date_range_match = date_range_pattern.search(user_input)
        
        # 修改时间范围处理逻辑
        if block_match:
            # 用户指定了具体的区块范围
            start_block = int(block_match.group(1))
            end_block = int(block_match.group(2))
            time_range_hint = f"Block range: {start_block} - {end_block}"
            print(f"Detected user-specified block range: {start_block} - {end_block}")
        elif date_range_match:
            # 用户指定了日期范围
            start_year, start_month, start_day = int(date_range_match.group(1)), int(date_range_match.group(2)), int(date_range_match.group(3))
            end_year, end_month, end_day = int(date_range_match.group(4)), int(date_range_match.group(5)), int(date_range_match.group(6))
            
            # 转换为日期对象
            try:
                start_date = datetime.datetime(start_year, start_month, start_day)
                end_date = datetime.datetime(end_year, end_month, end_day)
                # 设置end_date为当天结束时间
                end_date = end_date.replace(hour=23, minute=59, second=59)
                
                # 计算日期对应的区块范围
                start_block, end_block = self._date_to_block_range(start_date, end_date, current_block)
                time_range_hint = f"Date range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
                print(f"Detected date range: {time_range_hint}, mapped to blocks: {start_block} - {end_block}")
            except (ValueError, TypeError) as e:
                print(f"Error processing date range: {str(e)}")
                # 使用默认值
                end_block = current_block
                start_block = max(0, current_block - 7200)  # 默认一天的区块
                time_range_hint = "Recent history (could not process specified date range)"
        elif date_match:
            # 用户指定了单个日期
            year, month, day = int(date_match.group(1)), int(date_match.group(2)), int(date_match.group(3))
            
            # 转换为日期对象
            try:
                # 创建指定日期的开始和结束时间
                start_date = datetime.datetime(year, month, day)
                end_date = start_date.replace(hour=23, minute=59, second=59)
                
                # 计算日期对应的区块范围
                start_block, end_block = self._date_to_block_range(start_date, end_date, current_block)
                time_range_hint = f"Date: {start_date.strftime('%Y-%m-%d')}"
                print(f"Detected date: {time_range_hint}, mapped to blocks: {start_block} - {end_block}")
            except (ValueError, TypeError) as e:
                print(f"Error processing date: {str(e)}")
                # 使用默认值
                end_block = current_block
                start_block = max(0, current_block - 7200)  # 默认一天的区块
                time_range_hint = "Recent history (could not process specified date)"
        elif time_match:
            # 用户指定了时间范围（如"last hour"）
            amount_text = time_match.group(1)
            amount = 1
            if amount_text and amount_text.strip():
                try:
                    amount = int(amount_text.strip())
                except ValueError:
                    amount = 1
                    
            unit = time_match.group(2)
            time_range_hint = f"Last {amount} {unit}{'s' if amount > 1 else ''}"
            
            blocks_per_unit = {
                'hour': 300,    
                'minute': 5,      
                'day': 7200,     
                'week': 50400,    
                'month': 216000   
            }
            
            blocks_to_subtract = blocks_per_unit.get(unit, 300) * amount
            start_block = max(0, current_block - blocks_to_subtract)
            end_block = current_block
            print(f"Based on time range '{amount} {unit}{'s' if amount > 1 else ''}', calculated block range: {start_block} - {end_block}")
        else:
            # 用户没有指定时间范围，查询所有历史
            print("No time range specified, will analyze historical transactions")
            end_block = current_block
            
            # 先获取地址，以确定是否需要查询全部历史
            if address_match:
                addresses = [address_match.group()]
            else:
                try:
                    if "event" in user_input.lower() or "attack" in user_input.lower() or "hack" in user_input.lower():
                        addresses = self._safe_extract_address_from_search(user_input, "event")
                    else:
                        addresses = self._safe_extract_address_from_search(user_input, "any")
                except Exception as e:
                    print(f"Error during address search: {str(e)}")
                    addresses = []
            
            if addresses:
                try:
                    # 获取合约创建区块
                    address = Web3.to_checksum_address(addresses[0])
                    # 使用二分查找找到合约创建区块
                    start_block = self._find_contract_creation_block(address)
                    if start_block is None:
                        print("Could not determine contract creation block, using block 1")
                        start_block = 1
                    
                    # 查找最近交易区块作为结束区块
                    latest_tx_block = self.find_latest_transaction_block(address)
                    if latest_tx_block:
                        end_block = min(current_block, latest_tx_block + 100)  # 在最近交易后加一些区块作为缓冲
                        print(f"Using latest transaction block plus buffer: {end_block}")
                    else:
                        # 如果无法确定最近交易区块，从创建区块开始往后推
                        # 安全事件通常发生在一个较短的时间内
                        if "event" in user_input.lower() or "attack" in user_input.lower() or "hack" in user_input.lower():
                            # 对于安全事件，从创建区块开始往后推一周
                            end_block = min(current_block, start_block + 50400)  # 一周的区块数
                            print(f"Security event analysis: analyzing one week from creation block")
                        else:
                            # 对于一般分析，从创建区块开始往后推一天
                            end_block = min(current_block, start_block + 7200)  # 一天的区块数
                            print(f"General analysis: analyzing one day from creation block")
                    
                    time_range_hint = f"From block {start_block} to {end_block} (limited range)"
                except Exception as e:
                    print(f"Error finding block range: {str(e)}")
                    # 使用保守的默认值：从创建区块开始往后推一天
                    if start_block is not None:
                        end_block = min(current_block, start_block + 7200)  # 约1天的区块
                    else:
                        start_block = max(0, current_block - 7200)  # 如果连创建区块都找不到，才用当前区块往前推
                        end_block = current_block
                    time_range_hint = "Recent history (limited range)"
            else:
                # 如果没有找到地址，使用较小的默认范围
                start_block = max(0, current_block - 7200)  # 约1天的区块
                time_range_hint = "Recent history (limited range)"
                print("No valid address found, using recent history with limited range")
        
        # Check if it's an Ethereum address format
        address_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        address_match = address_pattern.search(user_input)
        
        # Check if it contains token identifier
        token_pattern = re.compile(r'\b(USDT|UNI|ETH|BTC|[A-Z]{2,10})\b')
        token_match = token_pattern.search(user_input)
        token_identifier = token_match.group(1) if token_match else None
        
        # Determine analysis type
        security_keywords = ['security', 'attack', 'hack', 'exploit', 'vulnerability', 'risk']
        interaction_keywords = ['interaction', 'call', 'behavior', 'trace']
        
        is_security_analysis = any(keyword in user_input.lower() for keyword in security_keywords)
        has_interaction_focus = any(keyword in user_input.lower() for keyword in interaction_keywords)
        
        # Step 1: LLM structured parsing
        llm_result = self._get_structured_parse(user_input)
        
        # Modify search logic
        if address_match:
            addresses = [address_match.group()]
        else:
            # Try to get address from LLM result
            addresses = []
            try:
                # 1. First try to search in the event database
                if "event" in user_input.lower() or "attack" in user_input.lower() or "hack" in user_input.lower():
                    print("Searching for security events...")
                    try:
                        addresses = self._safe_extract_address_from_search(user_input, "event")
                    except Exception as e:
                        print(f"Error during event search: {str(e)}")
                
                # 2. If event search fails, try general search
                if not addresses:
                    print(f"Performing general search...")
                    try:
                        addresses = self._safe_extract_address_from_search(user_input, "any")
                    except Exception as e:
                        print(f"Error during search: {str(e)}")
            
            except Exception as e:
                print(f"Error during search process: {str(e)}")
                addresses = []
        
        # Determine analysis type and focus
        analysis_type = "security_analysis" if is_security_analysis else (
            "transaction_analysis" if has_interaction_focus else "contract_analysis"
        )
        
        analysis_focus = []
        if is_security_analysis:
            analysis_focus.extend(["Security event analysis", "Interaction behavior analysis", "Code analysis"])
        if has_interaction_focus:
            analysis_focus.extend(["Interaction behavior analysis", "Fund flow"])
        if not analysis_focus:
            analysis_focus = ["Contract analysis"]
        
        # Build final result
        final_llm_result = {
            "token_identifier": addresses[0] if addresses else "",  # 保持向后兼容，使用第一个地址
            "time_range_hint": time_range_hint,
            "analysis_focus": list(set(analysis_focus)),
            "analysis_type": analysis_type,
            "user_input": user_input,
            "user_specified_blocks": block_match is not None or time_match is not None or date_match is not None or date_range_match is not None,
            "network": "ethereum"
        }
        
        final_rag_data = {
            'address': addresses[0] if addresses else "",  # 保持向后兼容，使用第一个地址
            'addresses': addresses,  # 保留完整的地址列表
            'start_block': start_block,
            'end_block': end_block,
            'raw_data': {'addresses': addresses} if addresses else None,
            'user_input': user_input,
            'network': "ethereum"
        }
        
        return final_llm_result, final_rag_data

    def _get_structured_parse(self, text: str) -> Dict:
        """使用LLM+规则混合解析"""
        # 规则引擎优先
        rule_result = self._rule_based_parse(text)
        if rule_result['confidence'] > 0.8:
            return rule_result

        try:
            response = self.client.chat.completions.create(
                model=self.MODELNAME,
                messages=[{
                    "role": "system",
                    "content": self.PROMPT_TEMPLATE.format(user_input=text)
                }]
            )
            
            content = response.choices[0].message.content.strip()
            
            # 处理可能包含的markdown代码块
            if content.startswith('```json'):
                content = content.replace('```json\n', '').replace('\n```', '')
            elif content.startswith('```'):
                content = content.replace('```\n', '').replace('\n```', '')
                
            # 尝试解析JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                print(f"JSON解析错误: {str(e)}")
                print(f"原始内容: {content}")
                # 检查是否包含USDT地址
                if "0xdAC17F958D2ee523a2206206994597C13D831ec7" in content:
                    return {
                        "token_identifier": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                        "analysis_focus": ["interaction behavior analysis", "fund flow"],
                        "analysis_type": "transaction_analysis"
                    }
                return {
                    "token_identifier": "",
                    "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                    "analysis_focus": ["fund flow"],
                    "analysis_type": "transaction_analysis"
                }
                
        except Exception as e:
            print(f"LLM调用出错: {str(e)}")
            return {
                "token_identifier": "",
                "time_range_hint": "",  # 这里留空，让外层的time_range_hint生效
                "analysis_focus": ["资金流向"],
                "analysis_type": "transaction_analysis"
            }

    def _rule_based_parse(self, text: str) -> Dict:
        """基于正则的快速解析"""
        patterns = {
            'token': r'\b([A-Z]{3,5})\b|(\bERC-20\s+token\s+[\w\s]+)',
            'time_range': r'in (\d+) days|past (\d+) months',
            'date': r'(\d{4})-(\d{1,2})-(\d{1,2})',  # 匹配 YYYY-MM-DD 格式
            'date_range': r'(\d{4})-(\d{1,2})-(\d{1,2})\s*(?:to|[-~])\s*(\d{4})-(\d{1,2})-(\d{1,2})',  # 匹配日期范围
            'focus': r'security event|漏洞|fund flow'
        }
        result = {
            'confidence': 0,
            'time_range_hint': '',  # 初始化为空字符串
            'token_identifier': '',
            'analysis_focus': ["fund flow"],
            'analysis_type': "transaction_analysis"
        }
        
        # 代币识别
        token_match = re.search(patterns['token'], text)
        if token_match:
            result['token_identifier'] = token_match.group(1) or token_match.group(2)
            result['confidence'] += 0.5
        
        # 日期识别
        date_range_match = re.search(patterns['date_range'], text)
        if date_range_match:
            start_date = f"{date_range_match.group(1)}-{date_range_match.group(2)}-{date_range_match.group(3)}"
            end_date = f"{date_range_match.group(4)}-{date_range_match.group(5)}-{date_range_match.group(6)}"
            result['time_range_hint'] = f"Date range: {start_date} to {end_date}"
            result['confidence'] += 0.3
        else:
            date_match = re.search(patterns['date'], text)
            if date_match:
                date_str = f"{date_match.group(1)}-{date_match.group(2)}-{date_match.group(3)}"
                result['time_range_hint'] = f"Date: {date_str}"
                result['confidence'] += 0.3
        
        return result

    def _get_entities_from_llm(self, query: str) -> Dict[str, List[str]]:
        """
        使用LLM从查询中提取相关实体，并按类型分类
        返回格式：{
            'tokens': ['WETH', 'USDC'],  # 代币对
            'pools': ['Uniswap V3: WETH/USDC'],  # 明确指定的池子
            'events': ['hack event name']  # 安全事件
        }
        """
        try:
            prompt = """Please analyze the following query and categorize blockchain-related entities into these types:
1. Trading pairs or individual tokens (e.g., "WETH-USDC", "WETH and USDC", "USDT")
2. Specific pool names if mentioned (e.g., "Balancer: B-stETH-STABLE pool")
3. Security events if mentioned (e.g., "Bybit hack")

Query: {query}

Return the result in the following JSON format, with no additional text:
{{
    "tokens": ["token1", "token2"],  // For trading pairs, include both tokens. For single token queries, include just one
    "pools": ["pool_name"],  // Specific pool names if mentioned
    "events": ["event_name"]  // Security event names if mentioned
}}
"""
            
            response = self.client.chat.completions.create(
                model=self.MODELNAME,
                messages=[{
                    "role": "system",
                    "content": prompt.format(query=query)
                }],
                temperature=0.1
            )
            
            content = response.choices[0].message.content.strip()
            
            # 处理JSON响应
            if content.startswith('```json'):
                content = content.replace('```json\n', '').replace('\n```', '')
            elif content.startswith('```'):
                content = content.replace('```\n', '').replace('\n```', '')
            
            result = json.loads(content)
            print(f"LLM entity extraction result: {result}")
            return result
            
        except Exception as e:
            print(f"Error in entity extraction: {str(e)}")
            return {"tokens": [], "pools": [], "events": []}

    def _safe_extract_address_from_search(self, query, search_type="any"):
        """
        针对代币对查询优化的地址搜索
        返回格式：List[str] - 地址列表
        """
        try:
            # 提取实体
            entities = self._get_entities_from_llm(query)
            
            # 1. 如果是安全事件查询
            if search_type == "event" or entities['events']:
                print("Searching for security event...")
                event_name = entities['events'][0] if entities['events'] else query
                event_results = RAG_INSTANCE.search(event_name)
                event_addresses = []
                
                for result in event_results:
                    if (isinstance(result, dict) and 
                        result.get('type') == 'event' and 
                        result.get('score', 0) >= 80):
                        address = result['address']
                        if Web3.is_address(address):
                            event_addresses.append(Web3.to_checksum_address(address))
                
                if event_addresses:
                    print(f"Found event addresses: {event_addresses}")
                    return event_addresses
            
            # 2. 如果有代币对，搜索交易池
            if len(entities['tokens']) == 2:
                token0, token1 = entities['tokens']
                pool_addresses = []
                
                # 构建常见DEX的池子名称模式
                pool_patterns = [
                    f"Uniswap V2: {token0}-{token1}",
                    f"Uniswap V3: {token0}/{token1}",
                    f"Balancer: {token0}-{token1}",
                    f"SushiSwap: {token0}-{token1}",
                    f"Curve: {token0}-{token1}"
                ]
                
                # 搜索所有可能的池子
                for pattern in pool_patterns:
                    pool_results = RAG_INSTANCE.search(pattern)
                    for result in pool_results:
                        if (isinstance(result, dict) and 
                            result.get('type') == 'pool' and 
                            result.get('score', 0) >= 80):
                            pool_address = result['address']
                            if Web3.is_address(pool_address):
                                pool_addresses.append(Web3.to_checksum_address(pool_address))
                
                # 去重
                pool_addresses = list(set(pool_addresses))
                if pool_addresses:
                    print(f"Found pool addresses: {pool_addresses}")
                    return pool_addresses
            
            # 3. 如果是单个代币
            elif len(entities['tokens']) == 1:
                token_results = RAG_INSTANCE.search(entities['tokens'][0])
                for result in token_results:
                    if isinstance(result, dict) and result.get('type') == 'token':
                        address = result['address']
                        if Web3.is_address(address):
                            return [Web3.to_checksum_address(address)]
            
            # 4. 如果以上都没有找到，尝试直接搜索
            print(f"Trying direct search with query: {query}")
            direct_results = RAG_INSTANCE.search(query)
            for result in direct_results:
                if isinstance(result, dict) and result.get('score', 0) >= 80:
                    address = result.get('address')
                    if address and Web3.is_address(address):
                        return [Web3.to_checksum_address(address)]
            
            print("No valid addresses found")
            return []
            
        except Exception as e:
            print(f"Error during address extraction: {str(e)}")
            traceback.print_exc()  # 添加这行来打印详细错误信息
            return []

    def _find_contract_creation_block(self, address: str, batch_size: int = 100000) -> Optional[int]:
        """
        使用二分查找找到合约创建区块
        """
        try:
            # 获取Web3提供者URL
            alchemy_url = os.getenv("ALCHEMY_URL")
            if not alchemy_url:
                alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
                if alchemy_api_key:
                    alchemy_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
                else:
                    # 尝试从网络配置获取
                    try:
                        network_config = settings.NETWORKS["ethereum"]
                        alchemy_url = network_config.get('rpc_url')
                    except Exception:
                        alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/demo"  # 默认值
            
            w3 = Web3(Web3.HTTPProvider(alchemy_url))
            current_block = w3.eth.block_number
            
            print(f"Searching for contract creation block for {address}")
            
            # 检查当前区块是否存在合约代码
            code = w3.eth.get_code(address)
            if code == b'':
                print("No contract code found at this address")
                return None
            
            left = 1
            right = current_block
            creation_block = None
            
            while left <= right:
                mid = (left + right) // 2
                
                try:
                    # 检查中间区块的代码
                    code = w3.eth.get_code(address, block_identifier=mid)
                    if code == b'':
                        # 合约在这个区块还不存在
                        left = mid + 1
                    else:
                        # 合约在这个区块存在，记录并继续向前搜索
                        creation_block = mid
                        right = mid - 1
                except Exception as e:
                    print(f"Error checking block {mid}: {str(e)}")
                    # 如果出错，缩小搜索范围
                    right = mid - 1
            
            if creation_block is not None:
                print(f"Found contract creation around block {creation_block}")
                return creation_block
            
            print("Could not determine exact creation block")
            return None
            
        except Exception as e:
            print(f"Error in contract creation block search: {str(e)}")
            return None

    def find_latest_transaction_block(self, address: str, max_blocks_back: int = 10000) -> Optional[int]:
        """
        查找地址的最近一笔交易所在区块
        
        参数:
        - address: 合约地址
        - max_blocks_back: 向前查找的最大区块数
        
        返回:
        - 最新交易所在区块号，如果未找到则返回None
        """
        try:
            from database import get_db
            from database.models import UserInteraction
            from sqlalchemy import desc
            
            db = next(get_db())
            
            # 1. 首先尝试数据库查询
            latest_tx = db.query(UserInteraction).filter(
                (UserInteraction.target_contract == address.lower()) | 
                (UserInteraction.caller_contract == address.lower())
            ).order_by(desc(UserInteraction.block_number)).first()
            
            if latest_tx:
                print(f"从数据库找到最近交易区块: {latest_tx.block_number}")
                return latest_tx.block_number
            
            # 2. 如果数据库没有记录，尝试通过API查询
            # 获取Web3提供者URL
            alchemy_url = os.getenv("ALCHEMY_URL")
            if not alchemy_url:
                alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
                if alchemy_api_key:
                    alchemy_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
                else:
                    # 尝试从网络配置获取
                    try:
                        network_config = settings.NETWORKS["ethereum"]
                        alchemy_url = network_config.get('rpc_url')
                    except Exception:
                        alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/demo"  # 默认值
            
            w3 = Web3(Web3.HTTPProvider(alchemy_url))
            current_block = w3.eth.block_number
            
            # 尝试使用Etherscan API查询
            try:
                network_config = settings.NETWORKS["ethereum"]
                api_key = network_config.get('explorer_key')
                if api_key:
                    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock={current_block - max_blocks_back}&endblock={current_block}&sort=desc&apikey={api_key}"
                    response = requests.get(url)
                    data = response.json()
                    
                    if data.get('status') == '1' and data.get('result'):
                        transactions = data.get('result', [])
                        if transactions:
                            latest_block = int(transactions[0].get('blockNumber', 0))
                            print(f"从Etherscan API找到最近交易区块: {latest_block}")
                            return latest_block
            except Exception as e:
                print(f"使用Etherscan API查询最近交易失败: {str(e)}")
            
            # 3. 如果上述方法都失败，使用二分查找法查询最近的交易
            return self._find_latest_tx_binary_search(address, current_block - max_blocks_back, current_block, w3)
        
        except Exception as e:
            print(f"查找最近交易区块失败: {str(e)}")
            return None

    def _find_latest_tx_binary_search(self, address: str, start_block: int, end_block: int, w3: Web3 = None) -> Optional[int]:
        """使用二分查找查询地址的最近交易区块"""
        try:
            if w3 is None:
                # 如果没有提供Web3实例，创建一个新的
                alchemy_url = os.getenv("ALCHEMY_URL")
                if not alchemy_url:
                    alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
                    if alchemy_api_key:
                        alchemy_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
                    else:
                        # 尝试从网络配置获取
                        try:
                            network_config = settings.NETWORKS["ethereum"]
                            alchemy_url = network_config.get('rpc_url')
                        except Exception:
                            alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/demo"  # 默认值
                
                w3 = Web3(Web3.HTTPProvider(alchemy_url))
                
            latest_block = None
            
            print(f"开始二分查找地址 {address} 的最近交易，范围: {start_block} - {end_block}")
            
            while start_block <= end_block:
                mid_block = (start_block + end_block) // 2
                
                # 查询中点附近的一批区块
                batch_size = min(50, end_block - mid_block + 1)
                has_tx = False
                
                for block_num in range(mid_block, mid_block + batch_size):
                    try:
                        # 获取区块
                        block = w3.eth.get_block(block_num, full_transactions=True)
                        
                        # 检查区块中的交易
                        for tx in block.transactions:
                            tx_to = tx.get('to', '')
                            tx_from = tx.get('from', '')
                            
                            if tx_to and tx_to.lower() == address.lower() or tx_from.lower() == address.lower():
                                has_tx = True
                                latest_block = block_num
                                break
                        
                        if has_tx:
                            break
                    except Exception as e:
                        print(f"检查区块 {block_num} 时出错: {str(e)}")
                        continue
                
                if has_tx:
                    # 向后查找更近的交易
                    start_block = mid_block + batch_size
                else:
                    # 向前查找
                    end_block = mid_block - 1
            
            if latest_block:
                print(f"找到最近交易区块: {latest_block}")
            else:
                print(f"未找到地址 {address} 的交易")
            
            return latest_block
        
        except Exception as e:
            print(f"二分查找最近交易区块失败: {str(e)}")
            return None

    def _date_to_block_range(self, start_date: datetime.datetime, end_date: datetime.datetime, current_block: int) -> Tuple[int, int]:
        """
        将日期范围转换为区块范围，使用以太坊API获取更准确的信息
        
        参数:
        - start_date: 开始日期
        - end_date: 结束日期
        - current_block: 当前区块号
        
        返回:
        - 开始区块号和结束区块号的元组
        """
        try:
            # 获取当前时间
            now = datetime.datetime.now()
            
            # 转换日期为时间戳 (Unix timestamp)
            start_timestamp = int(start_date.timestamp())
            end_timestamp = int(end_date.timestamp())
            current_timestamp = int(now.timestamp())
            
            # 获取以太坊API密钥
            alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
            etherscan_api_key = os.getenv("ETHERSCAN_API_KEY")
            
            # 如果环境变量中没有直接的API密钥，尝试从网络配置中获取
            if not etherscan_api_key:
                try:
                    network_config = settings.NETWORKS["ethereum"]
                    etherscan_api_key = network_config.get('explorer_key')
                    print(f"从网络配置中获取到API密钥: {etherscan_api_key is not None}")
                except Exception as e:
                    print(f"从网络配置获取API密钥失败: {str(e)}")
            
            alchemy_url = os.getenv("ALCHEMY_URL")
            if not alchemy_url and alchemy_api_key:
                alchemy_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
                
            start_block = None
            end_block = None
            
            print(f"转换日期: {start_date.strftime('%Y-%m-%d')} 到 {end_date.strftime('%Y-%m-%d')}")
            
            # 尝试使用Etherscan API
            if etherscan_api_key:
                try:
                    # 获取开始日期对应的区块
                    start_url = f"https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp={start_timestamp}&closest=before&apikey={etherscan_api_key}"
                    start_response = requests.get(start_url)
                    start_data = start_response.json()
                    
                    if start_data.get("status") == "1" and "result" in start_data:
                        start_block = int(start_data["result"])
                        print(f"Etherscan API - 开始日期区块: {start_block}")
                    
                    # 获取结束日期对应的区块
                    end_url = f"https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp={end_timestamp}&closest=before&apikey={etherscan_api_key}"
                    end_response = requests.get(end_url)
                    end_data = end_response.json()
                    
                    if end_data.get("status") == "1" and "result" in end_data:
                        end_block = int(end_data["result"])
                        print(f"Etherscan API - 结束日期区块: {end_block}")
                        
                except Exception as e:
                    print(f"Etherscan API调用出错: {str(e)}")
            
            # 如果Etherscan API失败，尝试使用Web3方法估算
            if start_block is None or end_block is None:
                print("使用估算方法计算区块范围...")
                # 使用前面获取的alchemy_url
                web3_provider_url = alchemy_url or os.getenv("ALCHEMY_URL")
                if not web3_provider_url:
                    web3_provider_url = "https://eth-mainnet.g.alchemy.com/v2/demo"  # 使用一个默认值，但可能会受到限制
                    print("警告：未找到有效的Web3提供者URL，使用默认值，可能受到限制")
                
                w3 = Web3(Web3.HTTPProvider(web3_provider_url))
                
                try:
                    # 获取当前区块信息
                    latest_block = w3.eth.get_block('latest')
                    latest_block_number = latest_block.number
                    latest_block_timestamp = latest_block.timestamp
                    
                    # 获取100个区块前的区块信息，计算平均出块时间
                    old_block = w3.eth.get_block(latest_block_number - 100)
                    old_block_timestamp = old_block.timestamp
                    
                    # 计算平均每秒出块数
                    time_diff = latest_block_timestamp - old_block_timestamp
                    blocks_per_second = 100 / time_diff if time_diff > 0 else 1/15
                    
                    print(f"计算得到的平均出块速率: {blocks_per_second:.6f} 块/秒")
                    
                    # 估算时间戳对应的区块
                    if start_block is None:
                        time_diff_start = current_timestamp - start_timestamp
                        blocks_diff_start = int(time_diff_start * blocks_per_second)
                        start_block = max(1, latest_block_number - blocks_diff_start)
                        print(f"估算开始日期区块: {start_block}")
                    
                    if end_block is None:
                        time_diff_end = current_timestamp - end_timestamp
                        blocks_diff_end = int(time_diff_end * blocks_per_second)
                        end_block = min(latest_block_number, latest_block_number - blocks_diff_end)
                        print(f"估算结束日期区块: {end_block}")
                
                except Exception as e:
                    print(f"Error in block range calculation: {str(e)}")
                    # 使用保守的默认值：从创建区块开始往后推一天
                    if start_block is not None:
                        end_block = min(current_block, start_block + 7200)  # 约1天的区块
                    else:
                        start_block = max(0, current_block - 7200)  # 如果连创建区块都找不到，才用当前区块往前推
                        end_block = current_block
                    time_range_hint = "Recent history (limited range)"
            
            # 处理未来日期的情况
            if start_timestamp > current_timestamp:
                start_block = current_block
            if end_timestamp > current_timestamp:
                end_block = current_block
            
            # 确保开始区块不大于结束区块
            if start_block > end_block:
                start_block, end_block = end_block, start_block
                
            # 确保区块号在有效范围内
            start_block = max(1, start_block)
            end_block = min(current_block, end_block)
            
            # 如果差距太大，限制一下范围
            if end_block - start_block > 1000000:  # 限制最大查询范围为100万个区块
                end_block = start_block + 1000000
            
            print(f"最终确定的区块范围: {start_block} - {end_block}")
            return start_block, end_block
        
        except Exception as e:
            print(f"Error converting date to block range: {str(e)}")
            traceback.print_exc()
            # 返回默认值：当前区块和一天前的区块
            return max(0, current_block - 7200), current_block