"""
EventNode与StandardSwapEvent数据转换工具
支持双向转换和数据类型适配
"""
from typing import Dict, List, Any, Union, Optional
from decimal import Decimal
import json
from ..config.ethereum_constants import FACTORY_MAP, get_protocol_name


class DataTypeConverter:
    """数据类型转换器"""
    
    @staticmethod
    def bigint_to_string(value: Union[str, int, Any]) -> str:
        """将TypeScript bigint转换为Python字符串"""
        if value is None:
            return "0"
        
        # 处理字符串形式的bigint
        if isinstance(value, str):
            # 去除可能的bigint后缀
            if value.endswith('n'):
                value = value[:-1]
            return value
        
        # 处理数字
        if isinstance(value, (int, float)):
            return str(int(value))
        
        # 尝试转换其他类型
        try:
            return str(int(value))
        except:
            return "0"
    
    @staticmethod
    def string_to_bigint_js(value: str) -> str:
        """将Python字符串转换为JavaScript bigint格式"""
        return f"{value}n"
    
    @staticmethod
    def normalize_address(address: str) -> str:
        """标准化以太坊地址格式"""
        if not address:
            return ""
        
        address = address.strip().lower()
        if not address.startswith("0x"):
            address = "0x" + address
        
        return address
    
    @staticmethod
    def validate_ethereum_address(address: str) -> bool:
        """验证以太坊地址格式"""
        if not address:
            return False
        
        normalized = DataTypeConverter.normalize_address(address)
        return len(normalized) == 42 and normalized.startswith("0x")


class EventNodeToStandardSwapConverter:
    """EventNode -> StandardSwapEvent 转换器"""
    
    def __init__(self):
        self.converter = DataTypeConverter()
    
    def convert(self, event_node: 'MEVEventNode') -> Dict[str, Any]:
        """将MEVEventNode转换为StandardSwapEvent格式"""
        if not event_node.is_swap_event():
            raise ValueError(f"EventNode不是swap事件: {event_node.properties.get('swap_event_type')}")
        
        # 验证必需字段
        validation_errors = event_node.validate_mev_data()
        if validation_errors:
            raise ValueError(f"EventNode数据验证失败: {validation_errors}")
        
        return {
            "poolAddress": self.converter.normalize_address(
                event_node.properties.get("pool_address", "")
            ),
            "protocol": event_node.properties.get("protocol", ""),
            "tokenIn": self.converter.normalize_address(
                event_node.properties.get("token_in", "")
            ),
            "tokenOut": self.converter.normalize_address(
                event_node.properties.get("token_out", "")
            ),
            "amountIn": event_node.properties.get("amount_in", "0"),
            "amountOut": event_node.properties.get("amount_out", "0"), 
            "sender": self.converter.normalize_address(
                event_node.properties.get("sender", "")
            ),
            "recipient": self.converter.normalize_address(
                event_node.properties.get("recipient", "")
            ),
            "ethFlag": event_node.properties.get("eth_flag", False)
        }
    
    def convert_batch(self, event_nodes: List['MEVEventNode']) -> List[Dict[str, Any]]:
        """批量转换EventNode列表"""
        results = []
        errors = []
        
        for i, node in enumerate(event_nodes):
            try:
                if node.is_swap_event():
                    results.append(self.convert(node))
            except Exception as e:
                errors.append(f"Node {i} conversion failed: {str(e)}")
        
        if errors:
            print(f"Warning: {len(errors)} nodes failed conversion: {errors[:5]}")  # 只显示前5个错误
        
        return results


class StandardSwapToEventNodeConverter:
    """StandardSwapEvent -> EventNode 转换器"""
    
    def __init__(self):
        self.converter = DataTypeConverter()
    
    def convert(self, 
                swap_event: Dict[str, Any],
                tx_hash: str,
                log_index: int,
                block_number: int,
                timestamp: int) -> 'MEVEventNode':
        """将StandardSwapEvent转换为MEVEventNode"""
        from ..graph.enhanced_event_node import create_mev_event_node_from_standard_swap
        
        return create_mev_event_node_from_standard_swap(
            swap_event, tx_hash, log_index, block_number, timestamp
        )
    
    def convert_batch(self,
                     swap_events: List[Dict[str, Any]],
                     tx_hash: str,
                     block_number: int,
                     timestamp: int) -> List['MEVEventNode']:
        """批量转换StandardSwapEvent列表"""
        results = []
        
        for i, swap_event in enumerate(swap_events):
            try:
                node = self.convert(swap_event, tx_hash, i, block_number, timestamp)
                results.append(node)
            except Exception as e:
                print(f"Warning: StandardSwapEvent {i} conversion failed: {str(e)}")
        
        return results


class ProtocolDetector:
    """协议检测器"""
    
    def __init__(self):
        self.factory_map = FACTORY_MAP
    
    def detect_protocol_from_address(self, pool_address: str) -> str:
        """根据池地址检测协议"""
        if not pool_address:
            return "Unknown"
        
        pool_address = pool_address.lower()
        
        # 直接查找factory映射
        for factory_addr, protocol in self.factory_map.items():
            if pool_address.startswith(factory_addr[:10]):  # 前缀匹配
                return protocol
        
        return "Unknown"
    
    def detect_protocol_from_event(self, event_name: str, contract_address: str) -> str:
        """根据事件名称和合约地址检测协议"""
        event_name = event_name.lower()
        
        # 先尝试从地址检测
        protocol = self.detect_protocol_from_address(contract_address)
        if protocol != "Unknown":
            return protocol
        
        # 根据事件名称模式匹配
        if "swap" in event_name:
            return "Generic_DEX"
        elif "exchange" in event_name:
            return "Curve"
        elif "transfer" in event_name:
            return "Token_Transfer"
        
        return "Unknown"


class FieldMappingValidator:
    """字段映射验证器"""
    
    # EventNode -> StandardSwapEvent 字段映射表
    FIELD_MAPPING = {
        "pool_address": "poolAddress",
        "protocol": "protocol", 
        "token_in": "tokenIn",
        "token_out": "tokenOut",
        "amount_in": "amountIn",
        "amount_out": "amountOut",
        "sender": "sender",
        "recipient": "recipient",
        "eth_flag": "ethFlag"
    }
    
    def validate_mapping(self, event_node_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证并转换字段映射"""
        result = {}
        missing_fields = []
        
        for event_field, standard_field in self.FIELD_MAPPING.items():
            if event_field in event_node_data:
                result[standard_field] = event_node_data[event_field]
            else:
                missing_fields.append(event_field)
        
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")
        
        return result
    
    def get_reverse_mapping(self) -> Dict[str, str]:
        """获取反向映射 (StandardSwapEvent -> EventNode)"""
        return {v: k for k, v in self.FIELD_MAPPING.items()}


# 便捷转换函数
def eventnode_to_standard_swap(event_node: 'MEVEventNode') -> Dict[str, Any]:
    """便捷函数：EventNode转StandardSwapEvent"""
    converter = EventNodeToStandardSwapConverter()
    return converter.convert(event_node)


def standard_swap_to_eventnode(swap_event: Dict[str, Any],
                              tx_hash: str,
                              log_index: int = 0,
                              block_number: int = 0,
                              timestamp: int = 0) -> 'MEVEventNode':
    """便捷函数：StandardSwapEvent转EventNode"""
    converter = StandardSwapToEventNodeConverter()
    return converter.convert(swap_event, tx_hash, log_index, block_number, timestamp)


def validate_conversion_integrity(original_swap: Dict[str, Any], 
                                converted_node: 'MEVEventNode') -> bool:
    """验证转换完整性"""
    try:
        # 双向转换测试
        back_to_swap = eventnode_to_standard_swap(converted_node)
        
        # 比较关键字段
        key_fields = ["poolAddress", "protocol", "tokenIn", "tokenOut", 
                     "sender", "recipient", "ethFlag"]
        
        for field in key_fields:
            if original_swap.get(field) != back_to_swap.get(field):
                return False
        
        # 比较金额字段（考虑类型转换）
        for amount_field in ["amountIn", "amountOut"]:
            original_amount = str(original_swap.get(amount_field, 0))
            converted_amount = back_to_swap.get(amount_field, "0")
            if original_amount != converted_amount:
                return False
        
        return True
    except Exception:
        return False 