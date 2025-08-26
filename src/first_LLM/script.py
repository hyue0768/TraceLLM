import json
import requests
import os
import time
from web3 import Web3
from pathlib import Path

# 导入配置
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.config.settings import settings

# 创建存储目录
OUTPUT_DIR = Path("src/first_LLM/label_RAG/assets/blockchains/ethereum")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 使用公共RPC而不是Ankr（因为Ankr需要API密钥）
RPC_URL = "https://eth.llamarpc.com"  # Llama节点是免费的、可靠的以太坊RPC
print(f"使用RPC URL: {RPC_URL}")
w3_eth = Web3(Web3.HTTPProvider(RPC_URL))

# 代币列表 (以太坊主网) - 使用checksum地址格式
TOKENS = {
    "WETH": Web3.to_checksum_address("0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
    "USDC": Web3.to_checksum_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb48"),
    "USDT": Web3.to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
    "DAI": Web3.to_checksum_address("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
    "WBTC": Web3.to_checksum_address("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"),
    # 添加更多流行代币
    "AAVE": Web3.to_checksum_address("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9"),
    "LINK": Web3.to_checksum_address("0x514910771AF9Ca656af840dff83E8264EcF986CA"),
    "UNI": Web3.to_checksum_address("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"),
    "COMP": Web3.to_checksum_address("0xc00e94Cb662C3520282E6f5717214004A7f26888"),
    "SNX": Web3.to_checksum_address("0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F"),
    "CRV": Web3.to_checksum_address("0xD533a949740bb3306d119CC777fa900bA034cd52"),
    "MKR": Web3.to_checksum_address("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2"),
    "SUSHI": Web3.to_checksum_address("0x6B3595068778DD592e39A122f4f5a5cF09C90fE2"),
    "1INCH": Web3.to_checksum_address("0x111111111117dC0aa78b770fA6A738034120C302"),
    "LDO": Web3.to_checksum_address("0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32")
}

# DEX合约地址 - 使用checksum地址格式
UNISWAP_V2_FACTORY = Web3.to_checksum_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
UNISWAP_V3_FACTORY = Web3.to_checksum_address("0x1F98431c8aD98523631AE4a59f267346ea31F984")
SUSHISWAP_FACTORY = Web3.to_checksum_address("0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac")
CURVE_REGISTRY = Web3.to_checksum_address("0x90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5")  # Curve Registry v2

# Factory ABIs
FACTORY_ABI = '[{"constant":true,"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"name":"pair","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}]'
UNISWAP_V3_FACTORY_ABI = '[{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint24","name":"fee","type":"uint24"}],"name":"getPool","outputs":[{"internalType":"address","name":"pool","type":"address"}],"stateMutability":"view","type":"function"}]'

# Pool ABI
POOL_ABI = '[{"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"fee","outputs":[{"internalType":"uint24","name":"","type":"uint24"}],"stateMutability":"view","type":"function"}]'

# Curve Registry ABI (简化版)
CURVE_REGISTRY_ABI = '''[
    {"name":"pool_count","outputs":[{"type":"uint256"}],"inputs":[],"stateMutability":"view","type":"function"},
    {"name":"pool_list","outputs":[{"type":"address"}],"inputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
    {"name":"get_pool_name","outputs":[{"type":"string"}],"inputs":[{"type":"address"}],"stateMutability":"view","type":"function"}
]'''

# 添加重试机制
def call_with_retry(func, *args, max_retries=3, retry_delay=2, **kwargs):
    """带重试机制的函数调用"""
    last_error = None
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_error = e
            print(f"尝试 {attempt+1}/{max_retries} 失败: {str(e)}")
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt)  # 指数退避
                print(f"等待 {sleep_time} 秒后重试...")
                time.sleep(sleep_time)
    
    # 所有重试都失败
    print(f"所有重试都失败: {str(last_error)}")
    return None


def get_uniswap_v2_pools():
    """获取Uniswap V2池子"""
    print("获取Uniswap V2池子...")
    factory = w3_eth.eth.contract(address=UNISWAP_V2_FACTORY, abi=FACTORY_ABI)
    pools = []
    
    # 从Token列表生成所有可能的代币对
    token_symbols = list(TOKENS.keys())
    for i in range(len(token_symbols)):
        for j in range(i+1, len(token_symbols)):
            token0_symbol = token_symbols[i]
            token1_symbol = token_symbols[j]
            token0 = TOKENS[token0_symbol]
            token1 = TOKENS[token1_symbol]
            
            try:
                print(f"检查Uniswap V2池子: {token0_symbol}-{token1_symbol}")
                pair_address = call_with_retry(factory.functions.getPair(token0, token1).call)
                
                if pair_address and pair_address != "0x0000000000000000000000000000000000000000":
                    pool_name = f"Uniswap V2: {token0_symbol}-{token1_symbol}"
                    pools.append({
                        "name": pool_name,
                        "address": pair_address,
                        "token0": {"symbol": token0_symbol, "address": token0},
                        "token1": {"symbol": token1_symbol, "address": token1}
                    })
                    print(f"找到池子: {pool_name} ({pair_address})")
            except Exception as e:
                print(f"获取Uniswap V2池子 {token0_symbol}-{token1_symbol} 时出错: {str(e)}")
    
    return pools


def get_sushiswap_pools():
    """获取SushiSwap池子"""
    print("获取SushiSwap池子...")
    factory = w3_eth.eth.contract(address=SUSHISWAP_FACTORY, abi=FACTORY_ABI)
    pools = []
    
    # 从Token列表生成所有可能的代币对
    token_symbols = list(TOKENS.keys())
    for i in range(len(token_symbols)):
        for j in range(i+1, len(token_symbols)):
            token0_symbol = token_symbols[i]
            token1_symbol = token_symbols[j]
            token0 = TOKENS[token0_symbol]
            token1 = TOKENS[token1_symbol]
            
            try:
                print(f"检查SushiSwap池子: {token0_symbol}-{token1_symbol}")
                pair_address = call_with_retry(factory.functions.getPair(token0, token1).call)
                
                if pair_address and pair_address != "0x0000000000000000000000000000000000000000":
                    pool_name = f"SushiSwap: {token0_symbol}-{token1_symbol}"
                    pools.append({
                        "name": pool_name,
                        "address": pair_address,
                        "token0": {"symbol": token0_symbol, "address": token0},
                        "token1": {"symbol": token1_symbol, "address": token1}
                    })
                    print(f"找到池子: {pool_name} ({pair_address})")
            except Exception as e:
                print(f"获取SushiSwap池子 {token0_symbol}-{token1_symbol} 时出错: {str(e)}")
    
    return pools


def get_uniswap_v3_pools():
    """获取Uniswap V3池子"""
    print("获取Uniswap V3池子...")
    factory = w3_eth.eth.contract(address=UNISWAP_V3_FACTORY, abi=UNISWAP_V3_FACTORY_ABI)
    fee_tiers = [500, 3000, 10000]  # 0.05%, 0.3%, 1%
    fee_names = {500: "0.05%", 3000: "0.3%", 10000: "1%"}
    pools = []
    
    # 从Token列表生成所有可能的代币对
    token_symbols = list(TOKENS.keys())
    for i in range(len(token_symbols)):
        for j in range(i+1, len(token_symbols)):
            token0_symbol = token_symbols[i]
            token1_symbol = token_symbols[j]
            token0 = TOKENS[token0_symbol]
            token1 = TOKENS[token1_symbol]
            
        for fee in fee_tiers:
                try:
                    print(f"检查Uniswap V3池子: {token0_symbol}-{token1_symbol} ({fee_names[fee]})")
                    pool_address = call_with_retry(factory.functions.getPool(token0, token1, fee).call)
                    
                    if pool_address and pool_address != "0x0000000000000000000000000000000000000000":
                        pool_name = f"Uniswap V3: {token0_symbol}-{token1_symbol} ({fee_names[fee]})"
                        pools.append({
                            "name": pool_name,
                            "address": pool_address,
                            "token0": {"symbol": token0_symbol, "address": token0},
                            "token1": {"symbol": token1_symbol, "address": token1},
                            "fee": fee
                        })
                        print(f"找到池子: {pool_name} ({pool_address})")
                except Exception as e:
                    print(f"获取Uniswap V3池子 {token0_symbol}-{token1_symbol} ({fee_names[fee]}) 时出错: {str(e)}")
    
    return pools


def get_curve_pools():
    """获取Curve池子"""
    print("获取Curve池子...")
    # 由于Curve Registry格式较复杂，使用静态列表替代
    curve_pools = [
        {
            "name": "Curve: 3pool",
            "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7"
        },
        {
            "name": "Curve: stETH",
            "address": "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"
        },
        {
            "name": "Curve: BUSD",
            "address": "0x79a8C46DeA5aDa233ABaFFD40F3A0A2B1e5A4F27"
        },
        {
            "name": "Curve: Compound",
            "address": "0xA2B47E3D5c44877cca798226B7B8118F9BFb7A56"
        },
        {
            "name": "Curve: USDN",
            "address": "0x0f9cb53Ebe405d49A0bbdBD291A65Ff571bC83e1"
        },
        {
            "name": "Curve: USDT",
            "address": "0x52EA46506B9CC5Ef470C5bf89f17Dc28bB35D85C"
        },
        {
            "name": "Curve: sBTC",
            "address": "0x7fC77b5c7614E1533320Ea6DDc2Eb61fa00A9714"
        },
        {
            "name": "Curve: renBTC",
            "address": "0x93054188d876f558f4a66B2EF1d97d16eDf0895B"
        }
    ]
    
    print(f"使用静态列表获取到 {len(curve_pools)} 个Curve池子")
    return curve_pools


def get_balancer_pools():
    """获取Balancer池子 (静态列表)"""
    print("获取Balancer池子...")
    # 由于Graph API可能不稳定，使用静态列表
    balancer_pools = [
        {
            "name": "Balancer: wstETH-WETH",
            "address": "0x32296969Ef14EB0c6d29669C550D4a0449130230"
        },
        {
            "name": "Balancer: 50WETH-50DAI",
            "address": "0x0b09deA16768f0799065C475bE02919503cB2a35"
        },
        {
            "name": "Balancer: 80BAL-20WETH",
            "address": "0x5c6Ee304399DBdB9C8Ef030aB642B10820DB8F56"
        },
        {
            "name": "Balancer: B-stETH-STABLE",
            "address": "0x32296969Ef14EB0c6d29669C550D4a0449130230"
        }
    ]
    
    print(f"使用静态列表获取到 {len(balancer_pools)} 个Balancer池子")
    return balancer_pools


def fetch_static_dex_pools():
    """使用静态数据直接创建JSON文件"""
    print("使用静态数据创建DEX池子列表...")
    
    # 静态数据 - 添加更多池子
    static_data = {
        "uniswap_v2": [
            {"name": "Uniswap V2: WETH-USDC", "address": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"},
            {"name": "Uniswap V2: WETH-USDT", "address": "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852"},
            {"name": "Uniswap V2: WETH-DAI", "address": "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"},
            {"name": "Uniswap V2: WETH-WBTC", "address": "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940"},
            {"name": "Uniswap V2: USDC-USDT", "address": "0x3041CbD36888bECc7bbCBc0045E3B1f144466f5f"},
            {"name": "Uniswap V2: WETH-UNI", "address": "0xd3d2E2692501A5c9Ca623199D38826e513033a17"},
            {"name": "Uniswap V2: WETH-LINK", "address": "0xa2107FA5B38d9bbd2C461D6EDf11B11A50F6b974"},
            {"name": "Uniswap V2: WETH-COMP", "address": "0xCFfDdeD873554F362Ac02f8Fb1f02E5ada10516f"},
            {"name": "Uniswap V2: WETH-AAVE", "address": "0xDFC14d2Af169B0D36C4EFF567Ada9b2E0CAE044f"},
            {"name": "Uniswap V2: WETH-SNX", "address": "0x43AE24960e5534731Fc831386c07755A2dc33D47"},
            {"name": "Uniswap V2: WETH-CRV", "address": "0x3dA1313aE46132A397D90d95B1424A9A7e3e0fCE"},
            {"name": "Uniswap V2: WETH-MKR", "address": "0xC2aDdA861F89bBB333c90c492cB837741916A225"},
            {"name": "Uniswap V2: WETH-SUSHI", "address": "0xCE84867c3c02B05dc570d0135103d3fB9CC19433"}
        ],
        "uniswap_v3": [
            {"name": "Uniswap V3: WETH-USDC (0.05%)", "address": "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"},
            {"name": "Uniswap V3: WETH-USDC (0.3%)", "address": "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8"},
            {"name": "Uniswap V3: WETH-USDT (0.3%)", "address": "0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36"},
            {"name": "Uniswap V3: WETH-DAI (0.3%)", "address": "0xC2e9F25Be6257c210d7Adf0D4Cd6E3E881ba25f8"},
            {"name": "Uniswap V3: WBTC-WETH (0.3%)", "address": "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD"},
            {"name": "Uniswap V3: WETH-UNI (0.3%)", "address": "0x1d42064Fc4Beb5F8aAF85F4617AE8b3b5B8Bd801"},
            {"name": "Uniswap V3: USDC-USDT (0.01%)", "address": "0x3416cF6C708Da44DB2624D63ea0AAef7113527C6"},
            {"name": "Uniswap V3: USDC-DAI (0.05%)", "address": "0x6c6Bc977E13Df9b0de53b251522280BB72383700"},
            {"name": "Uniswap V3: WETH-LINK (0.3%)", "address": "0xa6Cc3C2531FdaA6Ae1A3CA84c2855806728693e8"},
            {"name": "Uniswap V3: WETH-AAVE (0.3%)", "address": "0x5aB53EE1d50eeF2C1DD3d5402789cd27bB52c1bB"},
            {"name": "Uniswap V3: WETH-CRV (1%)", "address": "0x919Fa96e88d67499339577Fa202345436bcD5cfa"},
            {"name": "Uniswap V3: WETH-SNX (0.3%)", "address": "0xDaC8A8E6DBf8c690ec6815e0fF03491B2770255D"}
        ],
        "sushiswap": [
            {"name": "SushiSwap: WETH-USDC", "address": "0x397FF1542f962076d0BFE58eA045FfA2d347ACa0"},
            {"name": "SushiSwap: WETH-USDT", "address": "0x06da0fd433C1A5d7a4faa01111c044910A184553"},
            {"name": "SushiSwap: WETH-DAI", "address": "0xC3D03e4F041Fd4cD388c549Ee2A29a9E5075882f"},
            {"name": "SushiSwap: WETH-WBTC", "address": "0xCEfF51756c56CeFFCA006cD410B03FFC46dd3a58"},
            {"name": "SushiSwap: WETH-SUSHI", "address": "0x795065dCc9f64b5614C407a6EFDC400DA6221FB0"},
            {"name": "SushiSwap: WETH-AAVE", "address": "0xD75EA151a61d06868E31F8988D28DFE5E9df57B4"},
            {"name": "SushiSwap: WETH-YFI", "address": "0x088ee5007C98a9677165D78dD2109AE4a3D04d0C"},
            {"name": "SushiSwap: WETH-UNI", "address": "0xDafd66636E2561b0284EDdE37e42d192F2844D40"},
            {"name": "SushiSwap: WETH-LINK", "address": "0xC40D16476380e4037e6b1A2594cAF6a6cc8Da967"},
            {"name": "SushiSwap: WETH-SNX", "address": "0xA1d7b2d891e3A1f9ef4bBC5be20630C2FEB1c470"}
        ],
        "curve": [
            {"name": "Curve: 3pool", "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7"},
            {"name": "Curve: stETH", "address": "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"},
            {"name": "Curve: BUSD", "address": "0x79a8C46DeA5aDa233ABaFFD40F3A0A2B1e5A4F27"},
            {"name": "Curve: Compound", "address": "0xA2B47E3D5c44877cca798226B7B8118F9BFb7A56"},
            {"name": "Curve: USDN", "address": "0x0f9cb53Ebe405d49A0bbdBD291A65Ff571bC83e1"},
            {"name": "Curve: USDT", "address": "0x52EA46506B9CC5Ef470C5bf89f17Dc28bB35D85C"},
            {"name": "Curve: sBTC", "address": "0x7fC77b5c7614E1533320Ea6DDc2Eb61fa00A9714"},
            {"name": "Curve: renBTC", "address": "0x93054188d876f558f4a66B2EF1d97d16eDf0895B"},
            {"name": "Curve: sETH", "address": "0xc5424B857f758E906013F3555Dad202e4bdB4567"},
            {"name": "Curve: EURS", "address": "0x0Ce6a5fF5217e38315f87032CF90686C96627CAA"},
            {"name": "Curve: FRAX", "address": "0xd632f22692FaC7611d2AA1C0D552930D43CAEd3B"},
            {"name": "Curve: LUSD", "address": "0xEd279fDD11cA84bEef15AF5D39BB4d4bEE23F0cA"},
            {"name": "Curve: steCRV", "address": "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"},
            {"name": "Curve: tricrypto2", "address": "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46"}
        ],
        "balancer": [
            {"name": "Balancer: wstETH-WETH", "address": "0x32296969Ef14EB0c6d29669C550D4a0449130230"},
            {"name": "Balancer: 50WETH-50DAI", "address": "0x0b09deA16768f0799065C475bE02919503cB2a35"},
            {"name": "Balancer: 80BAL-20WETH", "address": "0x5c6Ee304399DBdB9C8Ef030aB642B10820DB8F56"},
            {"name": "Balancer: B-stETH-STABLE", "address": "0x32296969Ef14EB0c6d29669C550D4a0449130230"},
            {"name": "Balancer: 50WBTC-50WETH", "address": "0xA6F548DF93de924d73be7D25dC02554c6bD66dB5"},
            {"name": "Balancer: 60WETH-40DAI", "address": "0x0b09deA16768f0799065C475bE02919503cB2a35"},
            {"name": "Balancer: 50WETH-50USDC", "address": "0x96646936b91d6B9D7D0c47C496AfBF3D6ec7B6f8"},
            {"name": "Balancer: WETH-AAVE-USDC", "address": "0x7213a321F1855CF1779f42c0CD85d3D95291D34C"},
            {"name": "Balancer: 50WETH-50WBTC", "address": "0xA6F548DF93de924d73be7D25dC02554c6bD66dB5"},
            {"name": "Balancer: B-auraBAL-STABLE", "address": "0x3dd0843A028C86e0b760b1A76929d1C5Ef93a2dd"}
        ],
        "pancakeswap": [
            {"name": "PancakeSwap: WETH-USDC", "address": "0x9507c04B10486547584C37Bcbd931B2a4FeE9A41"},
            {"name": "PancakeSwap: WETH-USDT", "address": "0x16f3d41c8F33f87AEea1a27548Bar3c6B553aD0a"},
            {"name": "PancakeSwap: WETH-DAI", "address": "0xe022587831a5A49f8C9c37C8d736F16fb4E0e585"},
            {"name": "PancakeSwap: WETH-WBTC", "address": "0x9e91B45d1245d2D52aC92d3Ed793ccdA65DdE218"},
            {"name": "PancakeSwap: CAKE-WETH", "address": "0x24702086E5F29762b25Dd24358a413c996c21E65"}
        ],
        "dodo": [
            {"name": "DODO: WETH-USDC", "address": "0x75c23271661d9d143DCb617222BC4BEc783eff34"},
            {"name": "DODO: WETH-DAI", "address": "0x3058EF90929cb8180174D74C507176ccA6835D73"},
            {"name": "DODO: USDT-USDC", "address": "0xC9f93163c99695c6526b799EbcA2207Fdf7D61aD"}
        ],
        "fraxswap": [
            {"name": "FraxSwap: FRAX-WETH", "address": "0x1529876A9348D61C6c4a3EEe1fe6CcaF750Fa5A1"},
            {"name": "FraxSwap: FRAX-FXS", "address": "0xE1573B9D29e2183B1AF0e743Dc2754979A40D237"}
        ]
    }
    
    # 为每个DEX创建单独的JSON文件
    for dex_name, pools in static_data.items():
        if pools:
            output_file = OUTPUT_DIR / f"{dex_name}_pools.json"
            with open(output_file, "w") as f:
                json.dump(pools, f, indent=4)
            print(f"已保存 {len(pools)} 个 {dex_name} 池子到 {output_file}")
    
    # 创建合并文件
    all_pools = []
    for pools in static_data.values():
        all_pools.extend(pools)
    
    if all_pools:
        output_file = OUTPUT_DIR / "all_dex_pools.json"
        with open(output_file, "w") as f:
            json.dump(all_pools, f, indent=4)
        print(f"已保存总计 {len(all_pools)} 个池子到 {output_file}")
    
    return True


def main():
    """主函数"""
    print(f"开始获取DEX池子信息...")
    
    # 首先检查是否能连接到RPC
    try:
        chain_id = w3_eth.eth.chain_id
        print(f"成功连接到以太坊网络，链ID: {chain_id}")
        
        # 尝试动态获取池子信息
        try:
            pools_data = {
                "uniswap_v2": get_uniswap_v2_pools(),
                "uniswap_v3": get_uniswap_v3_pools(),
                "sushiswap": get_sushiswap_pools(),
                "curve": get_curve_pools(),
                "balancer": get_balancer_pools()
            }
            
            # 为每个DEX创建单独的JSON文件
            for dex_name, pools in pools_data.items():
                if pools:
                    output_file = OUTPUT_DIR / f"{dex_name}_pools.json"
                    with open(output_file, "w") as f:
                        json.dump(pools, f, indent=4)
                    print(f"已保存 {len(pools)} 个 {dex_name} 池子到 {output_file}")
            
            # 创建合并文件
            all_pools = []
            for pools in pools_data.values():
                all_pools.extend(pools)
            
            if all_pools:
                output_file = OUTPUT_DIR / "all_dex_pools.json"
                with open(output_file, "w") as f:
                    json.dump(all_pools, f, indent=4)
                print(f"已保存总计 {len(all_pools)} 个池子到 {output_file}")
                
        except Exception as e:
            print(f"动态获取池子信息失败: {str(e)}")
            print("将使用静态数据替代...")
            fetch_static_dex_pools()
            
    except Exception as e:
        print(f"无法连接到以太坊网络: {str(e)}")
        print("将使用静态数据替代...")
        fetch_static_dex_pools()


if __name__ == "__main__":
    main()
