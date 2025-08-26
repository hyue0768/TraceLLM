import json
import os
from typing import Dict, Optional, Tuple, List
from rapidfuzz import process, fuzz
from web3 import Web3
from config.settings import settings

class TokenRAGSystem:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.w3 = Web3(Web3.HTTPProvider(settings.ALCHEMY_ENDPOINT))
        # 初始化各个数据库
        self.token_db = self._build_token_database()
        self.event_db = self._build_event_database()
        self.exchange_db = self._build_exchange_database()
    
    def _build_token_database(self) -> Dict:
        """构建代币数据库"""
        token_db = {}
        assets_dir = os.path.join(self.base_dir, "assets")
        if not os.path.exists(assets_dir):
            return token_db
            
        for filename in os.listdir(assets_dir):
            if filename.endswith('.json'):
                address = filename.split('.')[0]
                if not self.w3.is_address(address):
                    continue
                with open(os.path.join(assets_dir, filename)) as f:
                    try:
                        data = json.load(f)
                        token_db[data['name'].lower()] = {
                            'type': 'token',
                            'data': data,
                            'address': address
                        }
                        token_db[data['symbol'].lower()] = {
                            'type': 'token',
                            'data': data,
                            'address': address
                        }
                    except:
                        continue
        return token_db

    def _build_event_database(self) -> Dict:
        """构建安全事件数据库"""
        event_db = {}
        event_dir = os.path.join(self.base_dir, "event")
        if not os.path.exists(event_dir):
            return event_db
            
        for filename in os.listdir(event_dir):
            if filename.endswith('.json'):
                address = filename.split('.')[0]
                if not self.w3.is_address(address):
                    continue
                with open(os.path.join(event_dir, filename)) as f:
                    try:
                        data = json.load(f)
                        event_db[data['name'].lower()] = {
                            'type': 'event',
                            'data': data,
                            'address': address
                        }
                    except:
                        continue
        return event_db

    def _build_exchange_database(self) -> Dict:
        """构建DEX池子数据库"""
        exchange_db = {}
        exchange_dir = os.path.join(self.base_dir, "exchange")
        if not os.path.exists(exchange_dir):
            return exchange_db
            
        # 处理所有DEX池子文件
        for filename in os.listdir(exchange_dir):
            if not filename.endswith('.json'):
                continue
                
            dex_type = filename.split('_')[0]  # 例如 uniswap_v2, balancer 等
            with open(os.path.join(exchange_dir, filename)) as f:
                try:
                    pools = json.load(f)
                    for pool in pools:
                        pool_name = pool['name'].lower()
                        # 统一池子数据格式
                        pool_data = {
                            'type': 'pool',
                            'dex': dex_type,
                            'data': pool,
                            'address': pool['address']
                        }
                        exchange_db[pool_name] = pool_data
                        
                        # 为Uniswap类池子添加代币对搜索
                        if 'token0' in pool and 'token1' in pool:
                            token_pair = f"{pool['token0']['symbol']}-{pool['token1']['symbol']}".lower()
                            exchange_db[token_pair] = pool_data
                            token_pair_rev = f"{pool['token1']['symbol']}-{pool['token0']['symbol']}".lower()
                            exchange_db[token_pair_rev] = pool_data
                except Exception as e:
                    print(f"处理{filename}时出错: {str(e)}")
                    continue
        return exchange_db

    def search(self, query: str) -> List[Dict]:
        """
        Comprehensive search across all data sources, ensuring a consistent data structure
        Returns a list of all relevant results, sorted by relevance
        """
        try:
            results = []
            clean_query = query.strip().lower() if query else ""
            
            # Check if query is empty
            if not clean_query:
                print("Search query is empty")
                return []
            
            # 1. Determine search priority based on query content
            if "event" in clean_query.lower() or "attack" in clean_query.lower() or "hack" in clean_query.lower() or "security" in clean_query.lower() or "事件" in clean_query or "攻击" in clean_query:
                search_order = [self.event_db, self.token_db, self.exchange_db]
                print("Prioritizing event database search")
            elif "pool" in clean_query.lower() or "liquidity" in clean_query.lower() or "池" in clean_query or "流动性" in clean_query:
                search_order = [self.exchange_db, self.token_db, self.event_db]
                print("Prioritizing exchange database search")
            else:
                search_order = [self.token_db, self.event_db, self.exchange_db]
                print("Using default search order (token first)")
            
            # Extract potential entity names using improved patterns
            import re
            entity_candidates = []
            
            # 1. Extract entities from "of X", "about X", "for X" patterns
            preposition_patterns = [
                r'(?:of|about|for|regarding|on)\s+([a-zA-Z0-9\s]+?)(?:\s+in\s+|\s+block|\s+during|\s*$)',
                r'(?:of|about|for|regarding|on)\s+([a-zA-Z0-9\s]+?)(?:\s+from\s+|\s+between|\s*$)',
                r'(?:of|about|for|regarding|on)\s+"([^"]+)"'
            ]
            
            for pattern in preposition_patterns:
                matches = re.search(pattern, query, re.IGNORECASE)
                if matches:
                    entity = matches.group(1).strip()
                    if entity and len(entity) > 3:  # Avoid very short entity names
                        entity_candidates.append(entity.lower())
            
            # 2. Look for noun phrases (adjacent words with at least one capitalized)
            # This helps catch entities like "neobank Infini"
            words = query.split()
            i = 0
            while i < len(words):
                # Start phrase if current word is capitalized or previous word is a good context clue
                context_clues = ["the", "of", "for", "on", "about", "by"]
                if (i < len(words) and (words[i][0].isupper() or 
                                       (i > 0 and words[i-1].lower() in context_clues))):
                    phrase_start = i
                    i += 1
                    # Continue phrase while words are adjacent and not stop words
                    stop_words = ["in", "on", "at", "block", "blocks", "from", "to", "during", "between", "the", "a", "an"]
                    while (i < len(words) and words[i].lower() not in stop_words 
                          and not words[i].startswith("block")):
                        i += 1
                    # Extract multi-word phrase
                    if i - phrase_start > 0:
                        phrase = " ".join(words[phrase_start:i]).lower()
                        if len(phrase) > 3 and phrase not in entity_candidates:
                            entity_candidates.append(phrase)
                else:
                    i += 1
            
            # Remove duplicates and very common words
            common_words = ["analysis", "security", "event", "attack", "hack"]
            entity_candidates = [e for e in entity_candidates if e.lower() not in common_words]
            
            # Print extracted entities
            print(f"Extracted entity candidates: {entity_candidates}")
            
            # 2. Exact matching with database keys
            exact_matches = []
            for db in search_order:
                if not db:  # Skip empty databases
                    continue
                    
                # First try exact matching with the full query
                if clean_query in db:
                    item_data = db[clean_query]
                    if isinstance(item_data, dict):
                        item_with_score = {
                            **item_data,
                            'score': 100  # Exact match score 100
                        }
                        exact_matches.append(item_with_score)
                
                # Then try exact matching with extracted entity names
                for entity in entity_candidates:
                    if entity in db:
                        item_data = db[entity]
                        if isinstance(item_data, dict):
                            item_with_score = {
                                **item_data,
                                'score': 95  # Entity exact match score 95
                            }
                            exact_matches.append(item_with_score)
            
            # 3. If no exact matches, perform fuzzy search
            if not exact_matches:
                fuzzy_matches = []
                # Search through databases in priority order
                for db in search_order:
                    if not db:  # Skip empty databases
                        continue
                    
                    # 3.1 Full query fuzzy search
                    try:
                        db_keys = list(db.keys())
                        matches = process.extract(clean_query, db_keys, scorer=fuzz.ratio, limit=3)
                        
                        for match_item in matches:
                            # Process the match item safely
                            if isinstance(match_item, tuple) and len(match_item) >= 2:
                                match, score = match_item[0], match_item[1]
                            else:
                                continue
                                
                            if score >= 80:  # Similarity threshold
                                item_data = db[match]
                                if isinstance(item_data, dict):
                                    item_with_score = {
                                        **item_data,
                                        'score': score
                                    }
                                    fuzzy_matches.append(item_with_score)
                    except Exception as e:
                        print(f"Error in fuzzy search with full query: {str(e)}")
                    
                    # 3.2 Entity-based fuzzy search
                    for entity in entity_candidates:
                        try:
                            # For multi-word entities, try token sort ratio which handles word order
                            if " " in entity:
                                score_method = fuzz.token_sort_ratio
                            else:
                                score_method = fuzz.ratio
                                
                            entity_matches = process.extract(entity, db_keys, scorer=score_method, limit=3)
                            
                            for match_item in entity_matches:
                                # Process the match item safely
                                if isinstance(match_item, tuple) and len(match_item) >= 2:
                                    match, score = match_item[0], match_item[1]
                                else:
                                    continue
                                    
                                if score >= 80:  # Similarity threshold
                                    item_data = db[match]
                                    # Bump up the score for entity matches to prioritize them
                                    modified_score = min(100, score + 5)
                                    if isinstance(item_data, dict):
                                        item_with_score = {
                                            **item_data,
                                            'score': modified_score
                                        }
                                        fuzzy_matches.append(item_with_score)
                                        print(f"Entity '{entity}' matched '{match}' with score {modified_score}")
                        except Exception as e:
                            print(f"Error in fuzzy search with entity '{entity}': {str(e)}")
                
                # Remove duplicates (items with same address) and keep highest score
                addr_to_item = {}
                for item in fuzzy_matches:
                    addr = item.get('address')
                    if addr and (addr not in addr_to_item or item.get('score', 0) > addr_to_item[addr].get('score', 0)):
                        addr_to_item[addr] = item
                
                # Sort by score and convert back to list
                fuzzy_matches = sorted(addr_to_item.values(), key=lambda x: x.get('score', 0), reverse=True)
                results = fuzzy_matches
            else:
                # If there are exact matches, use those results
                results = exact_matches
            
            # Ensure each result has the expected dictionary format
            validated_results = []
            for item in results:
                # Ensure necessary fields exist
                if not isinstance(item, dict):
                    print(f"Skipping non-dictionary search result: {type(item)}")
                    continue
                
                # Ensure address field exists and is valid
                if 'address' not in item or not item['address']:
                    print(f"Skipping search result missing valid address")
                    continue
                
                # Ensure type field exists
                if 'type' not in item:
                    print(f"Search result missing type field, using 'unknown'")
                    item['type'] = 'unknown'
                
                # Ensure data field exists
                if 'data' not in item:
                    print(f"Search result missing data field, adding empty dict")
                    item['data'] = {}
                
                validated_results.append(item)
            
            return validated_results
            
        except Exception as e:
            print(f"Error during search process: {str(e)}")
            import traceback
            traceback.print_exc()
            return []  # Return empty list on error, not None

    def search_with_block_range(self, query: str) -> Tuple[Optional[dict], Tuple[int, int]]:
        """增强版搜索：返回最相关的结果和区块范围，确保返回值一致性"""
        try:
            results = self.search(query)
            
            # 检查结果是否为空
            if not results:
                print(f"搜索 '{query}' 没有找到匹配结果")
                return None, (0, 0)
            
            # 使用第一个最相关的结果
            best_match = results[0]
            
            # 深度拷贝以避免修改原始数据
            import copy
            best_match_copy = copy.deepcopy(best_match)
            
            # 确保data字段存在，用于计算区块范围
            if 'data' not in best_match_copy or not isinstance(best_match_copy['data'], dict):
                best_match_copy['data'] = {'time_range_hint': ''}
            
            # 计算区块范围
            block_range = self._calculate_block_range(best_match_copy['data'])
        
            return best_match_copy, block_range
            
        except Exception as e:
            print(f"搜索与区块范围计算出错: {str(e)}")
            # 在出错情况下返回一致的格式
            return None, (0, 0)
        
    def _calculate_block_range(self, data: dict) -> Tuple[int, int]:
        """Maintain the original block range calculation logic but handle English time units"""
        try:
            latest_block = self.w3.eth.block_number
            
            BLOCKS_PER_MINUTE = 60 // 12
            BLOCKS_PER_HOUR = BLOCKS_PER_MINUTE * 60
            BLOCKS_PER_DAY = BLOCKS_PER_HOUR * 24
            BLOCKS_PER_WEEK = BLOCKS_PER_DAY * 7
            BLOCKS_PER_MONTH = BLOCKS_PER_DAY * 30
            
            time_range = data.get('time_range_hint', '').lower()
            
            # Handle English time units
            if 'minute' in time_range or 'min' in time_range:
                minutes = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_MINUTE * minutes
            elif 'hour' in time_range or 'hr' in time_range:
                hours = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_HOUR * hours
            elif 'day' in time_range:
                days = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_DAY * days
            elif 'week' in time_range:
                weeks = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_WEEK * weeks
            elif 'month' in time_range:
                months = int(''.join(filter(str.isdigit, time_range)) or 1)
                blocks = BLOCKS_PER_MONTH * months
            else:
                blocks = BLOCKS_PER_HOUR
                
            start_block = max(0, latest_block - blocks)
            return start_block, latest_block
            
        except Exception as e:
            print(f"Failed to calculate block range: {str(e)}")
            return latest_block - 300, latest_block

# 初始化实例
if not hasattr(TokenRAGSystem, '_instance'):
    TokenRAGSystem._instance = TokenRAGSystem(
        "/root/whole_pipeline/src/first_LLM/label_RAG/assets/blockchains/ethereum"
    )
RAG_INSTANCE = TokenRAGSystem._instance