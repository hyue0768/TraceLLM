from web3 import Web3
from configparser import ConfigParser
from datetime import datetime
import time
from database import Database

def get_web3():
    config = ConfigParser()
    config.read('config/config.ini')  # 确保路径正确
    return Web3(Web3.HTTPProvider(config['ethereum']['alchemy_url']))

def is_contract(w3, address):
    """判断地址是否为合约地址"""
    if not w3.is_address(address):
        raise ValueError(f"Invalid address: {address}")
    checksum_addr = w3.to_checksum_address(address)
    return len(w3.eth.get_code(checksum_addr)) > 3  # 合约代码长度阈值

def analyze_contract(target_address, k=100):
    """分析合约与用户交互的交易"""
    w3 = get_web3()
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Alchemy node")
    
    try:
        current_block = w3.eth.block_number
    except Exception as e:
        print(f"Error getting block number: {e}")
        return
    
    # 确保k的范围有效
    if k <= 0 or k > 10000:
        raise ValueError("k must be between 1 and 10000")
    
    db = Database()
    batch_data = []
    
    for i in range(k):
        block_num = current_block - i
        try:
            block = w3.eth.get_block(block_num, full_transactions=True)
            
            for tx in block.transactions:
                # 检查交易的目标地址是否是目标合约地址
                if tx.to and w3.to_checksum_address(tx.to) == w3.to_checksum_address(target_address):
                    if is_contract(w3, tx['from']):  # 如果发送者是合约地址
                        print(f"发现合约调用者：{tx['from']}")  # 输出合约调用者地址
                        # 保存交互数据
                        batch_data.append((target_address, tx['from'], block_num, datetime.fromtimestamp(block.timestamp)))
            
            # 每处理10个区块提交一次
            if i % 10 == 0 and batch_data:
                db.bulk_save(batch_data)
                batch_data = []
        
        except Exception as e:
            print(f"Error processing block {block_num}: {e}")
            continue
    
    # 提交剩余数据
    if batch_data:
        db.bulk_save(batch_data)

