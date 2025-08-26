"""
MEV数据验证器 - Step 1实施
提供完整的EventNode MEV数据验证规则
"""
from typing import Dict, List, Any, Optional, Tuple
from decimal import Decimal, InvalidOperation
import re
from enum import Enum
from ..config.ethereum_constants import get_major_tokens, FACTORY_MAP


class ValidationLevel(Enum):
    """验证级别"""
    BASIC = "basic"           # 基础验证：必需字段、格式
    STANDARD = "standard"     # 标准验证：数据完整性、逻辑一致性
    ENHANCED = "enhanced"     # 增强验证：MEV特定规则、协议验证
    STRICT = "strict"         # 严格验证：包含所有规则


class ValidationResult:
    """验证结果"""
    
    def __init__(self):
        self.is_valid = True
        self.errors = []
        self.warnings = []
        self.suggestions = []
        self.validation_level = ValidationLevel.BASIC
    
    def add_error(self, field: str, message: str):
        """添加错误"""
        self.is_valid = False
        self.errors.append({"field": field, "message": message})
    
    def add_warning(self, field: str, message: str):
        """添加警告"""
        self.warnings.append({"field": field, "message": message})
    
    def add_suggestion(self, field: str, message: str):
        """添加建议"""
        self.suggestions.append({"field": field, "message": message})
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "is_valid": self.is_valid,
            "validation_level": self.validation_level.value,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": self.errors,
            "warnings": self.warnings,
            "suggestions": self.suggestions
        }


class MEVDataValidator:
    """MEV数据验证器"""
    
    def __init__(self):
        self.ethereum_address_pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')
        self.tx_hash_pattern = re.compile(r'^0x[a-fA-F0-9]{64}$')
        self.major_tokens = set(token.lower() for token in get_major_tokens())
        self.known_factories = set(FACTORY_MAP.keys())
    
    def validate_eventnode(self, 
                          event_node: 'MEVEventNode', 
                          level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
        """验证MEVEventNode数据"""
        result = ValidationResult()
        result.validation_level = level
        
        # 基础验证
        self._validate_basic_fields(event_node, result)
        
        if level in [ValidationLevel.STANDARD, ValidationLevel.ENHANCED, ValidationLevel.STRICT]:
            self._validate_standard_fields(event_node, result)
        
        if level in [ValidationLevel.ENHANCED, ValidationLevel.STRICT]:
            self._validate_enhanced_fields(event_node, result)
        
        if level == ValidationLevel.STRICT:
            self._validate_strict_fields(event_node, result)
        
        return result
    
    def _validate_basic_fields(self, event_node: 'MEVEventNode', result: ValidationResult):
        """基础字段验证"""
        props = event_node.properties
        
        # 必需字段检查
        required_fields = [
            "event_name", "contract_address", "tx_hash", 
            "block_number", "timestamp"
        ]
        
        for field in required_fields:
            if not props.get(field):
                result.add_error(field, f"Required field '{field}' is missing or empty")
        
        # 地址格式验证
        address_fields = ["contract_address"]
        for field in address_fields:
            address = props.get(field)
            if address and not self._is_valid_ethereum_address(address):
                result.add_error(field, f"Invalid Ethereum address format: {address}")
        
        # 交易哈希验证
        tx_hash = props.get("tx_hash")
        if tx_hash and not self._is_valid_tx_hash(tx_hash):
            result.add_error("tx_hash", f"Invalid transaction hash format: {tx_hash}")
        
        # 数字字段验证
        if props.get("block_number") is not None:
            try:
                block_num = int(props["block_number"])
                if block_num < 0:
                    result.add_error("block_number", "Block number must be non-negative")
            except (ValueError, TypeError):
                result.add_error("block_number", "Block number must be a valid integer")
        
        if props.get("timestamp") is not None:
            try:
                timestamp = int(props["timestamp"])
                if timestamp < 0:
                    result.add_error("timestamp", "Timestamp must be non-negative")
            except (ValueError, TypeError):
                result.add_error("timestamp", "Timestamp must be a valid integer")
    
    def _validate_standard_fields(self, event_node: 'MEVEventNode', result: ValidationResult):
        """标准字段验证"""
        props = event_node.properties
        
        # 如果是swap事件，验证swap相关字段
        if event_node.is_swap_event():
            swap_required_fields = [
                "pool_address", "protocol", "token_in", "token_out",
                "amount_in", "amount_out", "sender", "recipient"
            ]
            
            for field in swap_required_fields:
                if not props.get(field):
                    result.add_error(field, f"Swap event missing required field: {field}")
            
            # 地址字段验证
            swap_address_fields = ["pool_address", "token_in", "token_out", "sender", "recipient"]
            for field in swap_address_fields:
                address = props.get(field)
                if address and not self._is_valid_ethereum_address(address):
                    result.add_error(field, f"Invalid address in swap field {field}: {address}")
            
            # 金额字段验证
            amount_fields = ["amount_in", "amount_out"]
            for field in amount_fields:
                amount = props.get(field, "0")
                if not self._is_valid_amount(amount):
                    result.add_error(field, f"Invalid amount format in {field}: {amount}")
                elif amount == "0":
                    result.add_warning(field, f"Amount in {field} is zero")
        
        # 事件类型一致性检查
        event_name = props.get("event_name", "").lower()
        swap_event_type = props.get("swap_event_type", "")
        
        if "swap" in event_name and "Non_Swap" in swap_event_type:
            result.add_warning("swap_event_type", 
                             "Event name suggests swap but type is Non_Swap")
    
    def _validate_enhanced_fields(self, event_node: 'MEVEventNode', result: ValidationResult):
        """增强字段验证"""
        props = event_node.properties
        
        # 协议验证
        protocol = props.get("protocol")
        if protocol and event_node.is_swap_event():
            if protocol not in ["UniswapV2", "UniswapV3", "SushiSwap", "Curve", 
                              "Balancer", "PancakeSwap", "1inch", "0x", "Generic_DEX"]:
                result.add_warning("protocol", f"Unknown protocol: {protocol}")
        
        # MEV相关字段验证
        if props.get("is_mev_relevant"):
            mev_fields = ["arbitrage_profit", "sandwich_position", "arbitrage_cycle_id"]
            if not any(props.get(field) for field in mev_fields):
                result.add_warning("is_mev_relevant", 
                                 "Marked as MEV relevant but no MEV fields set")
        
        # 金额合理性检查
        if event_node.is_swap_event():
            amount_in = props.get("amount_in", "0")
            amount_out = props.get("amount_out", "0")
            
            try:
                amount_in_decimal = Decimal(amount_in)
                amount_out_decimal = Decimal(amount_out)
                
                # 检查是否有一个金额为0（可能的错误）
                if amount_in_decimal == 0 or amount_out_decimal == 0:
                    result.add_warning("amounts", "One of the swap amounts is zero")
                
                # 检查金额是否过大（可能的精度错误）
                max_reasonable_amount = Decimal("10") ** 30  # 10^30
                if amount_in_decimal > max_reasonable_amount or amount_out_decimal > max_reasonable_amount:
                    result.add_warning("amounts", "Swap amount seems unreasonably large")
                
            except InvalidOperation:
                pass  # 金额格式错误已在标准验证中处理
        
        # 代币地址验证
        token_in = props.get("token_in")
        token_out = props.get("token_out")
        if token_in and token_out and token_in.lower() == token_out.lower():
            result.add_error("tokens", "tokenIn and tokenOut cannot be the same")
    
    def _validate_strict_fields(self, event_node: 'MEVEventNode', result: ValidationResult):
        """严格字段验证"""
        props = event_node.properties
        
        # 检查是否使用了主要代币
        if event_node.is_swap_event():
            token_in = props.get("token_in", "").lower()
            token_out = props.get("token_out", "").lower()
            
            if token_in not in self.major_tokens and token_out not in self.major_tokens:
                result.add_suggestion("tokens", 
                                    "Neither token is a major token, verify if this is expected")
        
        # 检查协议与池地址的一致性
        protocol = props.get("protocol")
        pool_address = props.get("pool_address", "").lower()
        
        if protocol and pool_address:
            expected_protocol = self._detect_protocol_from_pool(pool_address)
            if expected_protocol != "Unknown" and expected_protocol.lower() != protocol.lower():
                result.add_warning("protocol", 
                                 f"Protocol '{protocol}' may not match pool address pattern")
        
        # 数据完整性检查
        validation_errors = props.get("validation_errors", [])
        if validation_errors:
            for error in validation_errors:
                result.add_error("validation_errors", f"Internal validation error: {error}")
    
    def _is_valid_ethereum_address(self, address: str) -> bool:
        """验证以太坊地址格式"""
        return bool(address and self.ethereum_address_pattern.match(address))
    
    def _is_valid_tx_hash(self, tx_hash: str) -> bool:
        """验证交易哈希格式"""
        return bool(tx_hash and self.tx_hash_pattern.match(tx_hash))
    
    def _is_valid_amount(self, amount: str) -> bool:
        """验证金额格式"""
        try:
            Decimal(amount)
            return True
        except (InvalidOperation, TypeError, ValueError):
            return False
    
    def _detect_protocol_from_pool(self, pool_address: str) -> str:
        """从池地址检测协议（简化版）"""
        # 这里可以实现更复杂的协议检测逻辑
        for factory_addr, protocol in FACTORY_MAP.items():
            if pool_address.startswith(factory_addr[:10]):
                return protocol
        return "Unknown"
    
    def validate_standard_swap_event(self, swap_event: Dict[str, Any]) -> ValidationResult:
        """验证StandardSwapEvent格式数据"""
        result = ValidationResult()
        
        # 必需字段检查
        required_fields = [
            "poolAddress", "protocol", "tokenIn", "tokenOut",
            "amountIn", "amountOut", "sender", "recipient"
        ]
        
        for field in required_fields:
            if field not in swap_event or not swap_event[field]:
                result.add_error(field, f"Required field '{field}' is missing")
        
        # 地址字段验证
        address_fields = ["poolAddress", "tokenIn", "tokenOut", "sender", "recipient"]
        for field in address_fields:
            address = swap_event.get(field)
            if address and not self._is_valid_ethereum_address(address):
                result.add_error(field, f"Invalid address format: {address}")
        
        # 金额字段验证
        amount_fields = ["amountIn", "amountOut"]
        for field in amount_fields:
            amount = swap_event.get(field)
            if amount is not None:
                # 支持字符串和数字格式
                if not self._is_valid_amount(str(amount)):
                    result.add_error(field, f"Invalid amount format: {amount}")
        
        # ethFlag字段验证
        eth_flag = swap_event.get("ethFlag")
        if eth_flag is not None and not isinstance(eth_flag, bool):
            result.add_error("ethFlag", "ethFlag must be a boolean value")
        
        return result


# 便捷验证函数
def validate_mev_eventnode(event_node: 'MEVEventNode', 
                          level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
    """便捷函数：验证MEVEventNode"""
    validator = MEVDataValidator()
    return validator.validate_eventnode(event_node, level)


def validate_standard_swap(swap_event: Dict[str, Any]) -> ValidationResult:
    """便捷函数：验证StandardSwapEvent"""
    validator = MEVDataValidator()
    return validator.validate_standard_swap_event(swap_event)


def quick_validate_addresses(*addresses: str) -> List[Tuple[str, bool]]:
    """快速验证地址格式"""
    validator = MEVDataValidator()
    return [(addr, validator._is_valid_ethereum_address(addr)) for addr in addresses] 