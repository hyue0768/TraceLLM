import requests
import json
from web3 import Web3
from config.settings import settings
import rlp
from eth_utils import to_checksum_address

w3 = Web3(Web3.HTTPProvider(settings.ALCHEMY_ENDPOINT))

def get_contract_metadata(address):
    """获取合约元数据（包含ABI和源代码）"""
    url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={settings.ETHERSCAN_API_KEY}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == '1' and data['message'] == 'OK':
                return data['result'][0]
        return None
    except Exception as e:
        print(f"获取合约元数据失败 {address}: {e}")
        return None

def process_contract_metadata(metadata):
    """增强的元数据处理（支持多种源码格式）"""
    processed = {
        'abi': [],
        'source_code': '',
        'c_name': metadata.get('ContractName', 'Unnamed')
    }
    
    # 处理ABI
    try:
        if metadata.get('ABI') and metadata['ABI'] != 'Contract source code not verified':
            processed['abi'] = json.loads(metadata['ABI'])
    except Exception as e:
        print(f"ABI解析失败: {str(e)}")
    
    # 处理源代码
    source_code = metadata.get('SourceCode', '')
    if source_code.startswith('{{'):
        try:
            sources = json.loads(source_code[1:-1])
            processed['source_code'] = "\n\n".join(
                f"// File: {name}\n{content.get('content', '')}" 
                for name, content in sources.items() if isinstance(content, dict)  # 确保content是字典
            )
        except json.JSONDecodeError:
            print(f"源代码解析失败，返回原始内容: {source_code}")
            processed['source_code'] = source_code  # 返回原始内容
    else:
        if isinstance(source_code, str) and source_code:
            processed['source_code'] = source_code  # 直接赋值
        else:
            print("未找到有效的源代码")
    
    return processed