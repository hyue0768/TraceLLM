"""
以太坊主网MEV检测常量
替代Base链常量，专门用于以太坊主网的MEV检测
"""

# 基础链信息
ETHEREUM_CHAIN_ID = 1
V3_MAX_TICK = 887272
V3_MIN_TICK = -887272

# 主要代币地址 (以太坊主网)
WETH_ADDRESS = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
USDC_ADDRESS = "0xa0b86a33e6c0c8c80b96c1d7eee55821d47dcf57"  # USDC
USDT_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # USDT
DAI_ADDRESS = "0x6b175474e89094c44da98b954eedeac495271d0f"   # DAI
BUSD_ADDRESS = "0x4fabb145d64652a948d72533023f6e7a623c7c53"  # BUSD
FRAX_ADDRESS = "0x853d955acef822db058eb8505911ed77f175b99e"  # FRAX
LUSD_ADDRESS = "0x5f98805a4e8be255a32880fdec7f6728c6568ba0"  # LUSD
USDD_ADDRESS = "0x0c10bf8fcb7bf5412187a595ab97a3609160b5c6"  # USDD
USDP_ADDRESS = "0x8e870d67f660d95d5be530380d0ec0bd388289e1"  # USDP (PAX)

# DEX Factory地址 (以太坊主网)
UNISWAP_V2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
UNISWAP_V3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
SUSHISWAP_FACTORY = "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac"
PANCAKESWAP_V2_FACTORY = "0x1097053fd2ea711dad45caccc45eff7548fcb362"
PANCAKESWAP_V3_FACTORY = "0x41ff9aa7e16b8b1a8a8dc4f0efaab93d3d51c5d0"
CURVE_FACTORY = "0xb9fc157394af804a3578134a6585c0dc9cc990d4"
SHIBASWAP_FACTORY = "0x115934131916c8b277dd010ee02de363c09d037c"
DODO_FACTORY = "0x6b4fa0bc61eddc928e0df9c7f01e407bfcd3e5ef"
KYBER_FACTORY = "0x833e4083b7ae46ceb72f2684dd9e51c5b2e6b13a"

# DEX Router地址
UNISWAP_V2_ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
UNISWAP_V3_ROUTER = "0xe592427a0aece92de3edee1f18e0157c05861564"
SUSHISWAP_ROUTER = "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f"

# 其他重要协议地址
BALANCER_VAULT = "0xba12222222228d8ba445958a75a0704d566bf2c8"
ONE_INCH_V4_ROUTER = "0x1111111254fb6c44bac0bed2854e76f90643097d"
ZEROX_EXCHANGE_PROXY = "0xdef1c0ded9bec7f1a1670819833240f027b25eff"

# 已知的factory地址映射
FACTORY_MAP = {
    UNISWAP_V2_FACTORY.lower(): 'UniswapV2',
    UNISWAP_V3_FACTORY.lower(): 'UniswapV3', 
    SUSHISWAP_FACTORY.lower(): 'SushiSwap',
    PANCAKESWAP_V2_FACTORY.lower(): 'PancakeSwapV2',
    PANCAKESWAP_V3_FACTORY.lower(): 'PancakeSwapV3',
    CURVE_FACTORY.lower(): 'Curve',
    BALANCER_VAULT.lower(): 'BalancerV2',
    ONE_INCH_V4_ROUTER.lower(): '1inch',
    ZEROX_EXCHANGE_PROXY.lower(): '0x',
    SHIBASWAP_FACTORY.lower(): 'ShibaSwap',
    DODO_FACTORY.lower(): 'DODO',
    KYBER_FACTORY.lower(): 'Kyber'
}

# 主要流动性池地址 (以太坊主网)
UNISWAP_V3_WETH_USDC_500 = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"   # 0.05% fee
UNISWAP_V3_WETH_USDC_3000 = "0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8"  # 0.3% fee
UNISWAP_V3_WETH_USDC_10000 = "0x7bea39867e4169dbe237d55c8242a8f2fcdcc387" # 1% fee
UNISWAP_V2_WETH_USDC = "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"

# MEV检测参数
MIN_ARBITRAGE_PROFIT = 1000000000000000  # 0.001 ETH in wei
MAX_CYCLE_LENGTH = 8
MIN_SWAP_AMOUNT = 1000000000000000000   # 1 ETH in wei

# 协议识别关键词
DEX_METHOD_KEYWORDS = [
    'swap',
    'swapExactTokensForTokens', 
    'swapTokensForExactTokens',
    'swapExactETHForTokens',
    'swapETHForExactTokens',
    'swapExactTokensForETH',
    'swapTokensForExactETH',
    'exactInput',
    'exactInputSingle',
    'exactOutput',
    'exactOutputSingle',
    'multicall',
    'batchSwap',
    'exchange',
    'trade'
]

def get_protocol_name(factory_address: str) -> str:
    """根据factory地址获取协议名称"""
    return FACTORY_MAP.get(factory_address.lower(), 'Unknown')

def is_known_dex_factory(address: str) -> bool:
    """检查是否为已知的DEX factory地址"""
    return address.lower() in FACTORY_MAP

def get_major_tokens() -> list:
    """获取主要代币地址列表"""
    return [
        WETH_ADDRESS,
        USDC_ADDRESS, 
        USDT_ADDRESS,
        DAI_ADDRESS,
        BUSD_ADDRESS,
        FRAX_ADDRESS,
        LUSD_ADDRESS,
        USDD_ADDRESS,
        USDP_ADDRESS
    ]

def get_major_pools() -> list:
    """获取主要流动性池地址列表"""
    return [
        UNISWAP_V3_WETH_USDC_500,
        UNISWAP_V3_WETH_USDC_3000,
        UNISWAP_V3_WETH_USDC_10000,
        UNISWAP_V2_WETH_USDC
    ] 