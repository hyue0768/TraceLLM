from web3 import Web3
from web3.exceptions import ContractLogicError
from config.settings import settings

w3 = Web3(Web3.HTTPProvider(settings.ALCHEMY_ENDPOINT))

def get_bytecode(address):
    """获取合约字节码"""
    try:
        bytecode = w3.eth.get_code(Web3.to_checksum_address(address)).hex()
        return bytecode if bytecode != '0x' else None
    except ContractLogicError as e:
        print(f"获取字节码失败 {address}: {e}")
        return None
