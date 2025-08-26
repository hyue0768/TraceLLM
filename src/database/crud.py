from sqlalchemy.orm import Session
from database.models import Contract, UserInteraction
from sqlalchemy import or_, and_
from datetime import datetime

from sqlalchemy import desc
import time
import traceback

def upsert_contract(db: Session, contract_data: dict):
    """增强版插入/更新合约数据（新增decompiled_code处理）"""
    contract = db.query(Contract).filter(
        Contract.target_contract == contract_data['target_contract']
    ).first()
    
    # 处理decompiled_code格式 - 确保保存为JSON格式
    decompiled_raw = contract_data.get('decompiled_code', '')
    if isinstance(decompiled_raw, str) and decompiled_raw.strip():
        decompiled_formatted = {"code": decompiled_raw}
    elif isinstance(decompiled_raw, dict):
        decompiled_formatted = decompiled_raw
    else:
        decompiled_formatted = {"code": ""}
    
    update_data = {
        'target_contract': contract_data.get('target_contract', '').lower(),
        'source_code': contract_data.get('source_code', ''),
        'abi': contract_data.get('abi', '[]'),
        'bytecode': contract_data.get('bytecode', ''),
        'c_name': contract_data.get('contract_name', ''),
        'is_proxy': contract_data.get('is_proxy', False),
        'parent_address': contract_data.get('parent_address', None),
        'decompiled_code': contract_data.get('decompiled_code', '')
    }
    
    if contract:
        for key, value in update_data.items():
            setattr(contract, key, value)
    else:
        contract = Contract(**{**contract_data, **update_data})
        db.add(contract)
    
    db.commit()
    return contract

def update_decompiled_code(db: Session, target_contract: str, decompiled_code: str):
    """新增：更新反编译代码"""
    contract = db.query(Contract).filter(
        Contract.target_contract == target_contract
    ).first()
    if contract:
        contract.decompiled_code = decompiled_code
        db.commit()
        print(f"✅ 成功保存反编译代码到数据库，长度: {len(decompiled_code) if isinstance(decompiled_code, str) else 'N/A'}")
    return contract


def get_contract_full_info(db: Session, address: str):
    """
    递归获取合约完整信息（包含代理链）
    """
    contract = (
        db.query(Contract)
        .filter(Contract.target_contract == address.lower())
        .first()
    )
    if not contract:
        return None
    
    # 处理 decompiled_code 字段 - 简化处理
    decompiled_code = contract.decompiled_code
    
    result = {
        "address": contract.target_contract,
        "is_proxy": contract.is_proxy,
        "parent_address": contract.parent_address,
        "bytecode": contract.bytecode,
        "c_name": contract.c_name,
        "source_code": contract.source_code,
        "abi": contract.abi,
        "decompiled_code": decompiled_code
    }
    
    # 递归获取父合约信息（最多3层）
    if contract.is_proxy and contract.parent_address:
        parent_info = get_contract_full_info(db, contract.parent_address)
        if parent_info:
            result["parent_info"] = parent_info
    
    return result



def update_bytecode(db: Session, address: str, bytecode: str):
    contract = db.query(Contract).filter(Contract.target_contract == address).first()
    if contract:
        contract.bytecode = bytecode
        db.commit()
    return contract

def get_all_contract_abis_by_block(db: Session, block_number: int):
    """
    查询特定区块中的所有合约记录，并返回它们的 ABI
    :param db: 数据库会话
    :param block_number: 区块号
    :return: 包含所有合约 ABI 的列表（JSON 格式），如果未找到则返回空列表
    """
    contracts = (
        db.query(Contract)
        # .filter(Contract.block_number == block_number)  # 过滤特定区块
        .order_by(desc(Contract.created_at))  # 按创建时间降序排列
        # .all()  # 获取所有记录
        .first()
    )
    return [contract.abi for contract in contracts if contract.abi]  # 返回所有非空的 ABI

def get_latest_two_contract_abis(db: Session):
    """
    查询数据库中最新创建的两条合约记录，并返回它们的 ABI
    :param db: 数据库会话
    :return: 包含最新两条合约 ABI 的列表（JSON 格式），如果未找到则返回空列表
    """
    contracts = (
        db.query(Contract)
        # .order_by(desc(Contract.created_at))  # 按创建时间降序排列
        .limit(1)  # 限制查询结果为最新的两条记录
        .all()  # 获取所有符合条件的记录
    )
    return [contract.abi for contract in contracts if contract.abi]  # 返回所有非空的 ABI

def get_limit_contracts_source_code(db: Session):
    """
    查询数据库中最新创建的两条合约记录，并返回它们的 ABI
    :param db: 数据库会话
    :return: 包含最新两条合约 ABI 的列表（JSON 格式），如果未找到则返回空列表
    """
    contracts = (
        db.query(Contract)
        # .order_by(desc(Contract.created_at))  # 按创建时间降序排列
        .limit(20)  # 限制查询结果为最新的两条记录
        .all()  # 获取所有符合条件的记录
    )
    # 将每个 Contract 对象转换为字典
    contracts_dict = [contract.__dict__ for contract in contracts]
    return contracts_dict  # 返回所有非空的 ABI


def get_user_interactions(db: Session, limit: int = 1000):
    """
    获取用户交互数据
    :return: [
        {caller_contract, method_name, block_number, tx_hash, timestamp, input_data},
        ...
    ]
    """
    interactions = (
        db.query(UserInteraction)
        .order_by(desc(UserInteraction.timestamp))
        .limit(limit)
        .all()
    )
    return [{
        "target_contract": i.target_contract,
        "caller_contract": i.caller_contract,
        "method_name": i.method_name,
        "block_number": i.block_number,
        "tx_hash": i.tx_hash,
        "timestamp": i.timestamp,
        "input_data": i.input_data
    } for i in interactions]


def get_contract_source_code(db: Session, address: str):
    """
    根据合约地址获取源码
    """
    contract = (
        db.query(Contract)
        .filter(Contract.address == address)
        .first()
    )
    return contract.source_code if contract else None

def update_contract_type(db: Session, address: str, contract_type: str):
    """更新合约类型"""
    contract = db.query(Contract).filter(Contract.target_contract == address.lower()).first()
    if contract:
        contract.type = contract_type
        db.commit()
    return contract

def save_interaction(self, tx_data):
    """
    保存用户交互数据到数据库
    
    Args:
        tx_data: 包含交易数据的字典
        
    Returns:
        添加的记录ID
    """
    db = next(get_db())
    
    try:
        # 检查是否已存在
        existing = db.query(UserInteraction).filter(
            UserInteraction.tx_hash == tx_data['tx_hash']
        ).first()
        
        if existing:
            # 更新现有记录
            existing.input_data = tx_data.get('input_data', existing.input_data)
            existing.event_logs = tx_data.get('event_logs', existing.event_logs)
            
            # 如果有trace数据，更新
            if 'trace_data' in tx_data:
                existing.trace_data = tx_data['trace_data']
                
            # 更新新增字段（如果有）
            if 'transfer_amount' in tx_data:
                existing.transfer_amount = tx_data['transfer_amount']
            if 'token_address' in tx_data:
                existing.token_address = tx_data['token_address']
            if 'is_token_transfer' in tx_data:
                existing.is_token_transfer = tx_data['is_token_transfer']
                
            db.add(existing)
            db.commit()
            return existing.id
        else:
            # 创建新记录
            interaction = UserInteraction(
                target_contract=tx_data['target_contract'].lower(),
                caller_contract=tx_data['caller_contract'].lower(),
                method_name=tx_data['method_name'],
                block_number=tx_data['block_number'],
                tx_hash=tx_data['tx_hash'],
                timestamp=datetime.fromtimestamp(tx_data.get('timestamp', int(time.time()))),
                input_data=tx_data.get('input_data', ''),
                event_logs=tx_data.get('event_logs', None),
                trace_data=tx_data.get('trace_data', None),
                network=tx_data.get('network', 'ethereum'),
                transfer_amount=tx_data.get('transfer_amount', None),
                token_address=tx_data.get('token_address', None),
                is_token_transfer=tx_data.get('is_token_transfer', False)
            )
            db.add(interaction)
            db.commit()
            return interaction.id
            
    except Exception as e:
        db.rollback()
        print(f"保存交互数据时出错: {str(e)}")
        traceback.print_exc()
        return None