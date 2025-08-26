#!/usr/bin/env python3
"""
增强存储层集成适配器 - Enhanced Storage Integration Adapter
=========================================================

提供平滑的迁移路径，让现有代码能够逐步使用增强存储层，
同时保持向后兼容性。

功能特性：
- 透明的新旧存储切换
- 逐步迁移支持
- 性能监控
- 降级机制
"""

import logging
from typing import Optional, Dict, Any, Union, List
from sqlalchemy.orm import Session
from datetime import datetime

# 导入原有模块
from .crud import (
    upsert_contract as legacy_upsert_contract,
    get_contract_full_info as legacy_get_contract_full_info
)
from .models import Contract, UserInteraction

# 导入增强存储层
from .enhanced_storage import (
    EnhancedStorageManager,
    create_enhanced_storage,
    enhanced_upsert_contract,
    enhanced_save_interaction
)

logger = logging.getLogger(__name__)


class EnhancedStorageAdapter:
    """
    增强存储适配器
    
    提供统一的接口，自动处理新旧存储系统的切换，
    支持逐步迁移和性能对比。
    """
    
    def __init__(self, db_session: Session, 
                 use_enhanced: bool = True,
                 fallback_to_legacy: bool = True,
                 enable_performance_comparison: bool = False):
        """
        初始化适配器
        
        Args:
            db_session: 数据库会话
            use_enhanced: 是否优先使用增强存储
            fallback_to_legacy: 增强存储失败时是否降级到legacy
            enable_performance_comparison: 是否启用性能对比（会同时执行新旧方法）
        """
        self.db = db_session
        self.use_enhanced = use_enhanced
        self.fallback_to_legacy = fallback_to_legacy
        self.performance_comparison = enable_performance_comparison
        
        # 初始化增强存储管理器
        if self.use_enhanced:
            try:
                self.enhanced_storage = create_enhanced_storage(db_session)
                logger.info("增强存储适配器初始化成功")
            except Exception as e:
                logger.warning(f"增强存储初始化失败: {str(e)}")
                if not self.fallback_to_legacy:
                    raise
                self.enhanced_storage = None
                self.use_enhanced = False
        else:
            self.enhanced_storage = None
        
        # 性能统计
        self.stats = {
            'enhanced_success': 0,
            'enhanced_failure': 0,
            'legacy_success': 0,
            'legacy_failure': 0,
            'fallback_count': 0,
            'performance_comparisons': 0
        }
    
    # ========================================
    # 合约信息相关接口
    # ========================================
    
    def upsert_contract(self, contract_data: Dict[str, Any]) -> bool:
        """
        插入/更新合约信息（适配器版本）
        
        Args:
            contract_data: 合约数据字典
            
        Returns:
            bool: 操作是否成功
        """
        enhanced_success = False
        legacy_success = False
        
        # 尝试使用增强存储
        if self.use_enhanced and self.enhanced_storage:
            try:
                start_time = datetime.now()
                
                # 转换数据格式（如果需要）
                enhanced_data = self._convert_to_enhanced_format(contract_data)
                enhanced_success, error_msg = self.enhanced_storage.store_contract_info(enhanced_data)
                
                if enhanced_success:
                    self.enhanced_storage.commit_transaction()
                    self.stats['enhanced_success'] += 1
                    
                    enhanced_duration = (datetime.now() - start_time).total_seconds()
                    logger.debug(f"增强存储合约信息成功，耗时: {enhanced_duration:.3f}s")
                    
                    # 如果不需要性能对比，直接返回
                    if not self.performance_comparison:
                        return True
                else:
                    self.stats['enhanced_failure'] += 1
                    logger.warning(f"增强存储失败: {error_msg}")
                    
            except Exception as e:
                self.stats['enhanced_failure'] += 1
                logger.error(f"增强存储异常: {str(e)}")
                enhanced_success = False
        
        # 降级到legacy存储或性能对比
        if (not enhanced_success and self.fallback_to_legacy) or self.performance_comparison:
            try:
                start_time = datetime.now()
                
                legacy_upsert_contract(self.db, contract_data)
                legacy_success = True
                self.stats['legacy_success'] += 1
                
                legacy_duration = (datetime.now() - start_time).total_seconds()
                logger.debug(f"Legacy存储合约信息成功，耗时: {legacy_duration:.3f}s")
                
                if not enhanced_success:
                    self.stats['fallback_count'] += 1
                    logger.info("已降级到legacy存储")
                
            except Exception as e:
                self.stats['legacy_failure'] += 1
                logger.error(f"Legacy存储异常: {str(e)}")
                legacy_success = False
        
        # 性能对比记录
        if self.performance_comparison and enhanced_success and legacy_success:
            self.stats['performance_comparisons'] += 1
        
        return enhanced_success or legacy_success
    
    def get_contract_full_info(self, address: str) -> Optional[Dict[str, Any]]:
        """
        获取合约完整信息（适配器版本）
        
        Args:
            address: 合约地址
            
        Returns:
            合约信息字典或None
        """
        enhanced_result = None
        legacy_result = None
        
        # 尝试使用增强存储查询
        if self.use_enhanced and self.enhanced_storage:
            try:
                start_time = datetime.now()
                
                enhanced_result = self.enhanced_storage.get_contract_info(address)
                
                enhanced_duration = (datetime.now() - start_time).total_seconds()
                logger.debug(f"增强查询耗时: {enhanced_duration:.3f}s")
                
                if enhanced_result and not self.performance_comparison:
                    return enhanced_result
                    
            except Exception as e:
                logger.error(f"增强查询异常: {str(e)}")
        
        # 降级到legacy查询或性能对比
        if (not enhanced_result and self.fallback_to_legacy) or self.performance_comparison:
            try:
                start_time = datetime.now()
                
                legacy_result = legacy_get_contract_full_info(self.db, address)
                
                legacy_duration = (datetime.now() - start_time).total_seconds()
                logger.debug(f"Legacy查询耗时: {legacy_duration:.3f}s")
                
            except Exception as e:
                logger.error(f"Legacy查询异常: {str(e)}")
        
        # 返回最佳结果
        return enhanced_result or legacy_result
    
    # ========================================
    # 交互数据相关接口
    # ========================================
    
    def save_interaction(self, tx_data: Dict[str, Any]) -> bool:
        """
        保存交互数据（适配器版本）
        
        Args:
            tx_data: 交易数据字典
            
        Returns:
            bool: 操作是否成功
        """
        enhanced_success = False
        legacy_success = False
        
        # 尝试使用增强存储
        if self.use_enhanced and self.enhanced_storage:
            try:
                enhanced_success = self.enhanced_storage.store_interaction(tx_data)
                
                if enhanced_success:
                    self.enhanced_storage.commit_transaction()
                    self.stats['enhanced_success'] += 1
                    
                    # 如果不需要性能对比，直接返回
                    if not self.performance_comparison:
                        return True
                else:
                    self.stats['enhanced_failure'] += 1
                    
            except Exception as e:
                self.stats['enhanced_failure'] += 1
                logger.error(f"增强存储交互数据异常: {str(e)}")
        
        # 降级到legacy存储或性能对比
        if (not enhanced_success and self.fallback_to_legacy) or self.performance_comparison:
            try:
                # 使用原有的UserInteraction模型
                existing = self.db.query(UserInteraction).filter(
                    UserInteraction.tx_hash == tx_data['tx_hash']
                ).first()
                
                if existing:
                    # 更新现有记录
                    for key, value in tx_data.items():
                        if hasattr(existing, key) and value is not None:
                            setattr(existing, key, value)
                else:
                    # 创建新记录
                    new_interaction = UserInteraction(**{
                        k: v for k, v in tx_data.items() 
                        if hasattr(UserInteraction, k)
                    })
                    self.db.add(new_interaction)
                
                self.db.commit()
                legacy_success = True
                self.stats['legacy_success'] += 1
                
                if not enhanced_success:
                    self.stats['fallback_count'] += 1
                
            except Exception as e:
                self.stats['legacy_failure'] += 1
                logger.error(f"Legacy存储交互数据异常: {str(e)}")
                self.db.rollback()
        
        return enhanced_success or legacy_success
    
    # ========================================
    # 增强功能接口
    # ========================================
    
    def get_function_by_selector(self, selector: str) -> Optional[Dict[str, Any]]:
        """
        通过选择器获取函数信息（增强功能）
        
        Args:
            selector: 函数选择器
            
        Returns:
            函数信息字典或None
        """
        if not (self.use_enhanced and self.enhanced_storage):
            logger.warning("增强存储未启用，无法使用函数选择器查询")
            return None
        
        try:
            return self.enhanced_storage.get_function_by_selector(selector)
        except Exception as e:
            logger.error(f"查询函数选择器失败: {str(e)}")
            return None
    
    def get_event_by_topic0(self, topic0: str) -> Optional[Dict[str, Any]]:
        """
        通过topic0获取事件信息（增强功能）
        
        Args:
            topic0: 事件topic0哈希
            
        Returns:
            事件信息字典或None
        """
        if not (self.use_enhanced and self.enhanced_storage):
            logger.warning("增强存储未启用，无法使用事件topic0查询")
            return None
        
        try:
            return self.enhanced_storage.get_event_by_topic0(topic0)
        except Exception as e:
            logger.error(f"查询事件topic0失败: {str(e)}")
            return None
    
    def get_contract_creator(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        获取合约创建者信息（增强功能）
        
        Args:
            contract_address: 合约地址
            
        Returns:
            创建者信息字典或None
        """
        if not (self.use_enhanced and self.enhanced_storage):
            logger.warning("增强存储未启用，无法使用合约创建者查询")
            return None
        
        try:
            return self.enhanced_storage.get_contract_creator(contract_address)
        except Exception as e:
            logger.error(f"查询合约创建者失败: {str(e)}")
            return None
    
    # ========================================
    # 工具方法
    # ========================================
    
    def _convert_to_enhanced_format(self, contract_data: Dict[str, Any]) -> Dict[str, Any]:
        """将legacy格式转换为增强格式"""
        enhanced_data = {}
        
        # 地址映射
        if 'target_contract' in contract_data:
            enhanced_data['address'] = contract_data['target_contract']
        elif 'address' in contract_data:
            enhanced_data['address'] = contract_data['address']
        
        # 合约名称映射
        if 'c_name' in contract_data:
            enhanced_data['contract_name'] = contract_data['c_name']
        elif 'contract_name' in contract_data:
            enhanced_data['contract_name'] = contract_data['contract_name']
        
        # 直接映射的字段
        direct_mappings = [
            'abi', 'source_code', 'compiler_version', 'network',
            'verification_status', 'is_proxy', 'parent_address'
        ]
        
        for field in direct_mappings:
            if field in contract_data:
                enhanced_data[field] = contract_data[field]
        
        return enhanced_data
    
    def switch_to_enhanced(self):
        """切换到增强存储模式"""
        if not self.enhanced_storage:
            try:
                self.enhanced_storage = create_enhanced_storage(self.db)
                self.use_enhanced = True
                logger.info("已切换到增强存储模式")
            except Exception as e:
                logger.error(f"切换到增强存储失败: {str(e)}")
                return False
        else:
            self.use_enhanced = True
            logger.info("已启用增强存储模式")
        return True
    
    def switch_to_legacy(self):
        """切换到legacy存储模式"""
        self.use_enhanced = False
        logger.info("已切换到legacy存储模式")
    
    def get_adapter_stats(self) -> Dict[str, Any]:
        """获取适配器统计信息"""
        total_operations = sum(self.stats.values()) - self.stats['performance_comparisons']
        enhanced_ratio = (self.stats['enhanced_success'] / max(total_operations, 1)) * 100
        
        return {
            **self.stats,
            'total_operations': total_operations,
            'enhanced_success_ratio': f"{enhanced_ratio:.1f}%",
            'fallback_ratio': f"{(self.stats['fallback_count'] / max(total_operations, 1)) * 100:.1f}%",
            'current_mode': 'enhanced' if self.use_enhanced else 'legacy',
            'fallback_enabled': self.fallback_to_legacy,
            'performance_comparison_enabled': self.performance_comparison
        }
    
    def reset_stats(self):
        """重置统计信息"""
        for key in self.stats:
            self.stats[key] = 0
    
    def commit_transaction(self) -> bool:
        """提交事务"""
        try:
            if self.enhanced_storage:
                return self.enhanced_storage.commit_transaction()
            else:
                self.db.commit()
                return True
        except Exception as e:
            logger.error(f"提交事务失败: {str(e)}")
            self.db.rollback()
            return False


# ========================================
# 全局适配器实例管理
# ========================================

_global_adapter = None

def get_enhanced_adapter(db_session: Session, 
                        use_enhanced: bool = True,
                        create_new: bool = False) -> EnhancedStorageAdapter:
    """
    获取全局增强存储适配器实例
    
    Args:
        db_session: 数据库会话
        use_enhanced: 是否使用增强存储
        create_new: 是否创建新实例
        
    Returns:
        EnhancedStorageAdapter: 适配器实例
    """
    global _global_adapter
    
    if create_new or _global_adapter is None:
        _global_adapter = EnhancedStorageAdapter(
            db_session=db_session,
            use_enhanced=use_enhanced,
            fallback_to_legacy=True,
            enable_performance_comparison=False
        )
    
    return _global_adapter


# ========================================
# 兼容性接口（替换原有函数）
# ========================================

def adapter_upsert_contract(db_session: Session, contract_data: Dict[str, Any]) -> bool:
    """
    适配器版本的合约插入/更新接口
    
    可以直接替换原有的 upsert_contract 调用
    """
    adapter = get_enhanced_adapter(db_session)
    return adapter.upsert_contract(contract_data)


def adapter_get_contract_full_info(db_session: Session, address: str) -> Optional[Dict[str, Any]]:
    """
    适配器版本的合约信息查询接口
    
    可以直接替换原有的 get_contract_full_info 调用
    """
    adapter = get_enhanced_adapter(db_session)
    return adapter.get_contract_full_info(address)


def adapter_save_interaction(db_session: Session, tx_data: Dict[str, Any]) -> bool:
    """
    适配器版本的交互数据保存接口
    
    可以直接替换原有的 save_interaction 调用
    """
    adapter = get_enhanced_adapter(db_session)
    return adapter.save_interaction(tx_data)


if __name__ == "__main__":
    print("增强存储适配器模块已加载") 