import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DB_URL = os.getenv("DB_URL")
    # 保留这些配置以防某些地方仍需要（但主要使用本地节点）
    ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
    ALCHEMY_ENDPOINT = f"https://eth-mainnet.g.alchemy.com/v2/{os.getenv('ALCHEMY_API_KEY')}" if os.getenv('ALCHEMY_API_KEY') else ""
    
    APIKEY = os.getenv("APIKEY")
    BASEURL = os.getenv("BASEURL")
    PROMPT = os.getenv("PROMPT")
    MODELNAME = os.getenv("MODELNAME")
    DATASET_PROMPT = os.getenv("DATASET_PROMPT")

    # 本地节点配置
    LOCAL_NODE_URL = os.getenv("LOCAL_NODE_URL", "http://localhost:8545")
    
    # 外部trace服务配置（用于获取交易trace）
    EXTERNAL_TRACE_URL = os.getenv("EXTERNAL_TRACE_URL", "")  # 如果为空，使用Ankr
    ANKR_API_KEY = os.getenv("ANKR_API_KEY", "")
    
    # 增强模式配置 - 新增交易图构建器增强模式
    ENHANCED_GRAPH_MODE = os.getenv("ENHANCED_GRAPH_MODE", "auto").lower()  # auto, enabled, disabled
    ENHANCED_GRAPH_FALLBACK = os.getenv("ENHANCED_GRAPH_FALLBACK", "true").lower() == "true"  # 是否启用回退
    ENHANCED_GRAPH_ROLLOUT_PERCENTAGE = int(os.getenv("ENHANCED_GRAPH_ROLLOUT_PERCENTAGE", "0"))  # 灰度发布百分比 0-100
    
    # 网络配置 - 现在支持混合模式
    NETWORKS = {
        "ethereum": {
            "rpc_url": LOCAL_NODE_URL,  # 使用本地节点进行基础查询
            "trace_url": EXTERNAL_TRACE_URL or f"https://rpc.ankr.com/eth/{ANKR_API_KEY}" if ANKR_API_KEY else LOCAL_NODE_URL,  # trace专用URL
            "explorer_url": "https://api.etherscan.io/api",  # 重新启用Etherscan API用于日期转换
            "explorer_key": ETHERSCAN_API_KEY,  # 重新启用API Key
            "chain_id": 1,
            "use_local_node": False,  # 禁用本地节点，直接使用外部API获取trace
            "use_hybrid_mode": bool(ANKR_API_KEY or EXTERNAL_TRACE_URL),  # 是否启用混合模式
            "trace_api_key": ANKR_API_KEY  # trace服务的API密钥
        },
        "base": {
            "rpc_url": "https://mainnet.base.org",  # 如果需要的话保留
            "trace_url": "https://mainnet.base.org",
            "explorer_url": "https://api.etherscan.io/v2/api?chainid=8453",
            "explorer_key": ETHERSCAN_API_KEY,
            "chain_id": 8453,
            "use_local_node": False,
            "use_hybrid_mode": False,
            "trace_api_key": None
        }
    }

settings = Settings()