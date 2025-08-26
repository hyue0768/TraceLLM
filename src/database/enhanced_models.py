"""
增强的数据库模型，支持多层图系统的索引表
"""

from sqlalchemy import Column, String, JSON, BigInteger, TIMESTAMP, Boolean, Integer, Text, DECIMAL, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from typing import Optional, List, Dict, Any

Base = declarative_base()

class ContractSourceIndex(Base):
    """合约源码索引表"""
    __tablename__ = "contract_source_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    contract_address = Column(String(42), nullable=False, unique=True, index=True)
    source_code_hash = Column(String(64), index=True)  # 源码SHA256哈希
    source_code_index = Column(BigInteger)  # 源码在存储中的索引位置
    abi_hash = Column(String(64), index=True)  # ABI的SHA256哈希
    abi_index = Column(BigInteger)  # ABI在存储中的索引位置
    contract_name = Column(String(256))
    compiler_version = Column(String(64))
    network = Column(String(20), default='ethereum', index=True)
    verification_status = Column(String(20), default='unverified', index=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

class FunctionSignatureIndex(Base):
    """函数签名索引表"""
    __tablename__ = "function_signature_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    function_selector = Column(String(10), nullable=False, unique=True, index=True)  # 4字节选择器
    function_signature = Column(String(512), nullable=False, index=True)  # 完整函数签名
    function_name = Column(String(256), nullable=False, index=True)  # 函数名称
    parameter_types = Column(ARRAY(Text))  # 参数类型数组
    source_contract = Column(String(42), index=True)  # 首次发现该签名的合约
    usage_count = Column(Integer, default=1, index=True)  # 使用次数
    first_seen_block = Column(BigInteger)  # 首次发现的区块
    last_seen_block = Column(BigInteger)  # 最后发现的区块
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

class EventSignatureIndex(Base):
    """事件签名索引表"""
    __tablename__ = "event_signature_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_topic0 = Column(String(66), nullable=False, unique=True, index=True)  # 事件topic0
    event_signature = Column(String(512), nullable=False, index=True)  # 完整事件签名
    event_name = Column(String(256), nullable=False, index=True)  # 事件名称
    indexed_params = Column(ARRAY(Text))  # 索引参数类型
    non_indexed_params = Column(ARRAY(Text))  # 非索引参数类型
    source_contract = Column(String(42), index=True)  # 首次发现该事件的合约
    usage_count = Column(Integer, default=1, index=True)  # 使用次数
    first_seen_block = Column(BigInteger)  # 首次发现的区块
    last_seen_block = Column(BigInteger)  # 最后发现的区块
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

class ContractCreatorIndex(Base):
    """合约创建者索引表"""
    __tablename__ = "contract_creator_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    contract_address = Column(String(42), nullable=False, unique=True, index=True)
    creator_address = Column(String(42), nullable=False, index=True)
    creation_tx_hash = Column(String(66), nullable=False, index=True)
    creation_block_number = Column(BigInteger, nullable=False, index=True)
    creation_timestamp = Column(TIMESTAMP)
    constructor_params = Column(Text)  # 构造函数参数
    creation_value = Column(String(78))  # 创建时发送的ETH值
    factory_contract = Column(String(42), index=True)  # 工厂合约地址
    creation_method = Column(String(256))  # 创建方法
    network = Column(String(20), default='ethereum', index=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

class AddressLabelIndex(Base):
    """地址标签索引表"""
    __tablename__ = "address_label_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    address = Column(String(42), nullable=False, index=True)
    label_type = Column(String(50), nullable=False, index=True)  # exchange, defi, bridge等
    label_name = Column(String(256), index=True)  # 标签名称
    label_source = Column(String(50), index=True)  # 标签来源
    confidence_score = Column(DECIMAL(3,2), default=1.0)  # 置信度分数
    additional_info = Column(JSONB)  # 额外信息
    verified = Column(Boolean, default=False, index=True)  # 是否已验证
    network = Column(String(20), default='ethereum', index=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

class TokenInfoIndex(Base):
    """代币信息索引表"""
    __tablename__ = "token_info_index"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    token_address = Column(String(42), nullable=False, unique=True, index=True)
    token_symbol = Column(String(64), index=True)
    token_name = Column(String(256), index=True)
    token_decimals = Column(Integer)
    token_total_supply = Column(String(78))  # 总供应量
    token_type = Column(String(20), index=True)  # ERC20, ERC721, ERC1155等
    creator_address = Column(String(42), index=True)
    creation_block = Column(BigInteger)
    is_mintable = Column(Boolean, default=False)
    is_burnable = Column(Boolean, default=False)
    is_pausable = Column(Boolean, default=False)
    proxy_implementation = Column(String(42))  # 代理合约的实现地址
    network = Column(String(20), default='ethereum', index=True)
    verification_status = Column(String(20), default='unverified')
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

class MultiLayerGraphCache(Base):
    """多层图缓存表"""
    __tablename__ = "multilayer_graph_cache"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    cache_key = Column(String(128), nullable=False, unique=True, index=True)  # 缓存键
    target_contract = Column(String(42), nullable=False, index=True)
    start_block = Column(BigInteger, nullable=False)
    end_block = Column(BigInteger, nullable=False)
    graph_data = Column(JSONB, nullable=False)  # 图数据
    related_addresses = Column(ARRAY(Text))  # 相关地址数组
    analysis_type = Column(String(50))
    node_count = Column(Integer)
    layer_count = Column(Integer)
    network = Column(String(20), default='ethereum', index=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    expires_at = Column(TIMESTAMP, index=True)  # 缓存过期时间
    access_count = Column(Integer, default=0, index=True)  # 访问次数
    last_accessed = Column(TIMESTAMP, default=datetime.utcnow)

# 原有模型的保留和扩展
class Contract(Base):
    """合约表（原有模型的增强版）"""
    __tablename__ = "whole_pipeline"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    target_contract = Column(String(42), nullable=False, index=True)
    abi = Column(String(500000))
    source_code = Column(String(500000))
    c_name = Column(String(42), index=True)
    bytecode = Column(String(100000))
    decompiled_code = Column(String(500000))
    is_proxy = Column(Boolean, default=False, index=True)
    parent_address = Column(String(42), index=True) 
    network = Column(String(20), default='ethereum', index=True)
    type = Column(String(50))
    created_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)

class UserInteraction(Base):
    """用户交互表（原有模型的增强版）"""
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    target_contract = Column(String(42), nullable=False, index=True)
    caller_contract = Column(String(42), nullable=False, index=True)
    method_name = Column(String(255), nullable=False, index=True)
    block_number = Column(BigInteger, nullable=False, index=True)
    tx_hash = Column(String(66), unique=True, index=True)
    timestamp = Column(TIMESTAMP, index=True)
    input_data = Column(String(500000))
    event_logs = Column(JSON)
    trace_data = Column(JSON)
    network = Column(String(20), default='ethereum', index=True)
    transfer_amount = Column(String(66))
    token_address = Column(String(42), index=True)
    is_token_transfer = Column(Boolean, default=False, index=True)

# 数据访问层的辅助函数
class IndexedDataAccess:
    """数据访问层，提供快速查询方法"""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def get_contract_source_by_address(self, address: str) -> Optional[ContractSourceIndex]:
        """通过地址快速获取合约源码信息"""
        return self.db.query(ContractSourceIndex).filter(
            ContractSourceIndex.contract_address == address.lower()
        ).first()
    
    def get_function_by_selector(self, selector: str) -> Optional[FunctionSignatureIndex]:
        """通过函数选择器快速获取函数信息"""
        return self.db.query(FunctionSignatureIndex).filter(
            FunctionSignatureIndex.function_selector == selector
        ).first()
    
    def get_event_by_topic0(self, topic0: str) -> Optional[EventSignatureIndex]:
        """通过事件topic0快速获取事件信息"""
        return self.db.query(EventSignatureIndex).filter(
            EventSignatureIndex.event_topic0 == topic0
        ).first()
    
    def get_contract_creator(self, contract_address: str) -> Optional[ContractCreatorIndex]:
        """快速获取合约创建者信息"""
        return self.db.query(ContractCreatorIndex).filter(
            ContractCreatorIndex.contract_address == contract_address.lower()
        ).first()
    
    def get_address_labels(self, address: str, label_type: str = None) -> List[AddressLabelIndex]:
        """获取地址的标签信息"""
        query = self.db.query(AddressLabelIndex).filter(
            AddressLabelIndex.address == address.lower()
        )
        if label_type:
            query = query.filter(AddressLabelIndex.label_type == label_type)
        return query.all()
    
    def get_token_info(self, token_address: str) -> Optional[TokenInfoIndex]:
        """获取代币信息"""
        return self.db.query(TokenInfoIndex).filter(
            TokenInfoIndex.token_address == token_address.lower()
        ).first()
    
    def get_cached_graph(self, cache_key: str) -> Optional[MultiLayerGraphCache]:
        """获取缓存的多层图数据"""
        return self.db.query(MultiLayerGraphCache).filter(
            MultiLayerGraphCache.cache_key == cache_key,
            MultiLayerGraphCache.expires_at > datetime.utcnow()
        ).first()
    
    def update_graph_cache_access(self, cache_key: str):
        """更新图缓存的访问计数"""
        cache_record = self.db.query(MultiLayerGraphCache).filter(
            MultiLayerGraphCache.cache_key == cache_key
        ).first()
        if cache_record:
            cache_record.access_count += 1
            cache_record.last_accessed = datetime.utcnow()
            self.db.commit()
    
    def batch_upsert_function_signatures(self, signatures: List[Dict[str, Any]]):
        """批量插入或更新函数签名"""
        for sig in signatures:
            existing = self.get_function_by_selector(sig['function_selector'])
            if existing:
                existing.usage_count += 1
                existing.last_seen_block = sig.get('last_seen_block', existing.last_seen_block)
            else:
                new_sig = FunctionSignatureIndex(**sig)
                self.db.add(new_sig)
        self.db.commit()
    
    def batch_upsert_event_signatures(self, events: List[Dict[str, Any]]):
        """批量插入或更新事件签名"""
        for event in events:
            existing = self.get_event_by_topic0(event['event_topic0'])
            if existing:
                existing.usage_count += 1
                existing.last_seen_block = event.get('last_seen_block', existing.last_seen_block)
            else:
                new_event = EventSignatureIndex(**event)
                self.db.add(new_event)
        self.db.commit()
    
    def get_contracts_by_creator(self, creator_address: str) -> List[ContractCreatorIndex]:
        """获取特定创建者创建的所有合约"""
        return self.db.query(ContractCreatorIndex).filter(
            ContractCreatorIndex.creator_address == creator_address.lower()
        ).all()
    
    def get_interactions_in_block_range(
        self, 
        target_contract: str, 
        start_block: int, 
        end_block: int
    ) -> List[UserInteraction]:
        """获取指定区块范围内的交互记录"""
        return self.db.query(UserInteraction).filter(
            UserInteraction.target_contract == target_contract.lower(),
            UserInteraction.block_number >= start_block,
            UserInteraction.block_number <= end_block
        ).all()
    
    def get_most_used_functions(self, limit: int = 100) -> List[FunctionSignatureIndex]:
        """获取使用最多的函数"""
        return self.db.query(FunctionSignatureIndex).order_by(
            FunctionSignatureIndex.usage_count.desc()
        ).limit(limit).all()
    
    def get_most_used_events(self, limit: int = 100) -> List[EventSignatureIndex]:
        """获取使用最多的事件"""
        return self.db.query(EventSignatureIndex).order_by(
            EventSignatureIndex.usage_count.desc()
        ).limit(limit).all()

# 缓存键生成函数
def generate_graph_cache_key(
    target_contract: str,
    start_block: int,
    end_block: int,
    analysis_type: str = "full",
    additional_params: Dict[str, Any] = None
) -> str:
    """生成多层图缓存键"""
    import hashlib
    
    key_parts = [
        target_contract.lower(),
        str(start_block),
        str(end_block),
        analysis_type
    ]
    
    if additional_params:
        # 将额外参数按键排序后加入
        sorted_params = sorted(additional_params.items())
        key_parts.extend([f"{k}:{v}" for k, v in sorted_params])
    
    key_string = "|".join(key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:32]

# 数据库迁移辅助函数
def migrate_existing_data(db_session):
    """将现有数据迁移到新的索引表中"""
    
    # 1. 从现有contracts表迁移到contract_source_index
    print("迁移合约源码索引...")
    contracts = db_session.query(Contract).all()
    for contract in contracts:
        existing_index = db_session.query(ContractSourceIndex).filter(
            ContractSourceIndex.contract_address == contract.target_contract
        ).first()
        
        if not existing_index:
            source_index = ContractSourceIndex(
                contract_address=contract.target_contract,
                contract_name=contract.c_name,
                network=contract.network or 'ethereum',
                verification_status='verified' if contract.source_code else 'unverified'
            )
            db_session.add(source_index)
    
    # 2. 从现有交互记录提取函数签名
    print("提取函数签名索引...")
    interactions = db_session.query(UserInteraction).filter(
        UserInteraction.input_data.isnot(None),
        UserInteraction.input_data != ''
    ).all()
    
    function_signatures = {}
    for interaction in interactions:
        if interaction.input_data and len(interaction.input_data) >= 10:
            selector = interaction.input_data[:10]
            if selector not in function_signatures:
                function_signatures[selector] = {
                    'function_selector': selector,
                    'function_signature': f"{interaction.method_name}()",
                    'function_name': interaction.method_name,
                    'source_contract': interaction.target_contract,
                    'usage_count': 1,
                    'first_seen_block': interaction.block_number,
                    'last_seen_block': interaction.block_number
                }
            else:
                function_signatures[selector]['usage_count'] += 1
                function_signatures[selector]['last_seen_block'] = max(
                    function_signatures[selector]['last_seen_block'],
                    interaction.block_number
                )
    
    # 批量插入函数签名
    for sig_data in function_signatures.values():
        existing = db_session.query(FunctionSignatureIndex).filter(
            FunctionSignatureIndex.function_selector == sig_data['function_selector']
        ).first()
        if not existing:
            sig = FunctionSignatureIndex(**sig_data)
            db_session.add(sig)
    
    db_session.commit()
    print("数据迁移完成")

if __name__ == "__main__":
    # 示例用法
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # 这里需要替换为实际的数据库连接字符串
    # engine = create_engine("postgresql://user:password@localhost/dbname")
    # Base.metadata.create_all(engine)
    # Session = sessionmaker(bind=engine)
    # db = Session()
    # 
    # # 使用索引数据访问层
    # data_access = IndexedDataAccess(db)
    # 
    # # 示例查询
    # function_info = data_access.get_function_by_selector("0xa9059cbb")
    # print(f"Function: {function_info.function_name if function_info else 'Not found'}")
    
    pass 