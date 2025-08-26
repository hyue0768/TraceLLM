from sqlalchemy import Column, String, JSON, BigInteger, TIMESTAMP,Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Contract(Base):
    __tablename__ = "whole_pipeline"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    target_contract = Column(String(42), nullable=False)
    abi = Column(String(500000))  # 修改：从JSON改为String(500000)
    source_code = Column(String(500000))  # 修改：从JSON改为String(500000) 
    c_name = Column(String(42))
    bytecode = Column(String(500000))  # 修改：从String(100000)增加到String(500000)
    decompiled_code = Column(String(500000))  # 修改：从JSON改为String(500000)
    is_proxy = Column(Boolean, default=False)        # 新增字段
    parent_address = Column(String(42), index=True) 
    network = Column(String(20), default='ethereum')  # 新增：记录网络信息
    type = Column(String(50))  # 新增：记录合约类型
    created_at = Column(TIMESTAMP)  # 添加创建时间字段

class UserInteraction(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    target_contract = Column(String(42), nullable=False)
    caller_contract = Column(String(42), nullable=False)
    method_name = Column(String(255), nullable=False)
    block_number = Column(BigInteger, nullable=False)
    tx_hash = Column(String(66), unique=True)
    timestamp = Column(TIMESTAMP)
    input_data = Column(String(500000))  # 修改：从String(20000)增加到String(500000)
    event_logs = Column(JSON)  # 存储交易收据中的事件日志
    trace_data = Column(JSON)  # 新增：存储交易追踪数据
    network = Column(String(20), default='ethereum')  # 固定为以太坊网络
    transfer_amount = Column(String(66))  # 新增：存储转账金额（字符串格式，可以处理大数值）
    token_address = Column(String(42))   # 新增：存储代币地址（对于ETH转账，可存为NULL或特定值）
    is_token_transfer = Column(Boolean, default=False)  # 新增：标识是否为代币转账