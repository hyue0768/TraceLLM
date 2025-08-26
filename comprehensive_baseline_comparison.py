#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合基线对比系统（包含深度学习方法）

集成传统机器学习基线和深度学习基线，使用统一的LOGO交叉验证进行评估。
"""

import os
import sys
import glob
import json
import numpy as np
import pandas as pd
import logging
import warnings
from datetime import datetime
from typing import Dict, List, Tuple, Any
from sklearn.model_selection import LeaveOneGroupOut

# 忽略警告
warnings.filterwarnings('ignore')

# 导入基线方法
sys.path.append('/home/os/shuzheng/whole_pipeline')
from baseline_comparison import (
    DepthBasedMethod, RarityBasedMethod, SemanticBasedMethod, RandomMethod,
    MLBasedMethod, compute_attack_hit_rate_baseline, load_and_prepare_data
)

# 检查PyTorch是否可用
try:
    import torch
    from deep_learning_baselines import create_mlp_baseline, create_transformer_baseline
    PYTORCH_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info(f"PyTorch可用，设备: {torch.device('cuda' if torch.cuda.is_available() else 'cpu')}")
except ImportError:
    PYTORCH_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("PyTorch未安装，将跳过深度学习基线")

# 检查其他依赖
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("Scikit-learn未安装，将跳过传统ML基线")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logger.warning("XGBoost未安装，将跳过XGBoost基线")

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class UnifiedBaselineWrapper:
    """统一的基线方法包装器"""
    
    def __init__(self, method, method_type='traditional'):
        self.method = method
        self.method_type = method_type
        self.name = getattr(method, 'name', str(method))
    
    def fit(self, X: pd.DataFrame, y: np.ndarray, groups: np.ndarray = None):
        """训练模型"""
        if self.method_type == 'deep_learning':
            self.method.fit(X, y, groups)
        else:
            # 传统方法
            self.method.fit(X, y, groups)
    
    def predict_scores(self, X: pd.DataFrame, groups: np.ndarray = None) -> np.ndarray:
        """预测分数"""
        return self.method.predict_scores(X, groups)


def evaluate_unified_method(wrapper: UnifiedBaselineWrapper, 
                          df: pd.DataFrame, 
                          groups: np.ndarray, 
                          k: int = 30) -> Dict[str, Any]:
    """使用LOGO评估统一基线方法"""
    logger.info(f"评估方法: {wrapper.name} (类型: {wrapper.method_type})")
    
    logo = LeaveOneGroupOut()
    per_file_results = {}
    y = df['label'].values
    
    for train_idx, test_idx in logo.split(df, y, groups):
        train_df = df.iloc[train_idx]
        test_df = df.iloc[test_idx]
        test_groups = groups[test_idx]
        
        # 获取测试文件名
        test_file = test_groups[0]
        
        logger.info(f"  训练: {len(train_df)} 样本, 测试: {test_file} ({len(test_df)} 样本)")
        
        try:
            # 训练模型
            wrapper.fit(train_df, y[train_idx], groups[train_idx])
            
            # 预测测试集
            test_scores = wrapper.predict_scores(test_df, test_groups)
            
            # 计算指标
            test_df_with_scores = test_df.copy()
            test_df_with_scores['score'] = test_scores
            
            file_metrics = compute_attack_hit_rate_baseline(test_df_with_scores, k)
            per_file_results[test_file] = file_metrics
            
            logger.info(f"    {test_file}: 命中率={file_metrics['attack_hit_rate']:.3f}, "
                       f"F1={file_metrics['f1']:.3f}, 选择={file_metrics['actual_k']}/{file_metrics['total_paths_after_dedup']}")
            
        except Exception as e:
            logger.error(f"    {test_file} 评估失败: {e}")
            # 添加默认结果避免后续计算错误
            per_file_results[test_file] = {
                'attack_hit_rate': 0.0, 'precision': 0.0, 'recall': 0.0, 
                'accuracy': 0.0, 'f1': 0.0, 'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0,
                'total_attack_paths': 0, 'hit_attack_paths': 0, 'actual_k': 0,
                'total_paths_after_dedup': 0
            }
            continue
    
    # 计算全局指标
    if per_file_results:
        # Macro-averaged
        valid_results = [r for r in per_file_results.values() if r['f1'] >= 0]
        if valid_results:
            macro_attack_hit_rate = np.mean([r['attack_hit_rate'] for r in valid_results])
            macro_precision = np.mean([r['precision'] for r in valid_results])
            macro_recall = np.mean([r['recall'] for r in valid_results])
            macro_f1 = np.mean([r['f1'] for r in valid_results])
            macro_accuracy = np.mean([r['accuracy'] for r in valid_results])
        else:
            macro_attack_hit_rate = macro_precision = macro_recall = macro_f1 = macro_accuracy = 0.0
        
        # Micro-averaged
        total_tp = sum(r['TP'] for r in per_file_results.values())
        total_fp = sum(r['FP'] for r in per_file_results.values())
        total_fn = sum(r['FN'] for r in per_file_results.values())
        total_tn = sum(r['TN'] for r in per_file_results.values())
        
        micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        micro_accuracy = (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn) if (total_tp + total_tn + total_fp + total_fn) > 0 else 0.0
        micro_f1 = 2 * micro_precision * micro_recall / (micro_precision + micro_recall) if (micro_precision + micro_recall) > 0 else 0.0
        
        # 全局攻击路径命中率
        total_attacks = sum(r['total_attack_paths'] for r in per_file_results.values())
        total_hits = sum(r['hit_attack_paths'] for r in per_file_results.values())
        global_attack_hit_rate = total_hits / total_attacks if total_attacks > 0 else 0.0
    else:
        macro_attack_hit_rate = macro_precision = macro_recall = macro_f1 = macro_accuracy = 0.0
        micro_precision = micro_recall = micro_accuracy = micro_f1 = 0.0
        global_attack_hit_rate = 0.0
    
    return {
        'method_name': wrapper.name,
        'method_type': wrapper.method_type,
        'per_file_results': per_file_results,
        'macro_metrics': {
            'attack_hit_rate': macro_attack_hit_rate,
            'precision': macro_precision,
            'recall': macro_recall,
            'f1': macro_f1,
            'accuracy': macro_accuracy
        },
        'micro_metrics': {
            'attack_hit_rate': global_attack_hit_rate,
            'precision': micro_precision,
            'recall': micro_recall,
            'f1': micro_f1,
            'accuracy': micro_accuracy
        },
        'total_files': len(per_file_results)
    }


def main():
    """主函数"""
    input_dir = "/home/os/shuzheng/whole_pipeline/path_datasets_labeled"
    output_dir = f"/home/os/shuzheng/whole_pipeline/comprehensive_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    k = 20  # Top-30
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info("=" * 60)
    logger.info("综合基线对比系统启动（包含深度学习）")
    logger.info("=" * 60)
    logger.info(f"输入目录: {input_dir}")
    logger.info(f"输出目录: {output_dir}")
    logger.info(f"Top-K: {k}")
    
    # 加载数据
    try:
        df, groups = load_and_prepare_data(input_dir)
    except Exception as e:
        logger.error(f"加载数据失败: {e}")
        return 1
    
    # 收集所有基线方法
    methods = []
    
    # 1. 经典单特征基线
    methods.extend([
        UnifiedBaselineWrapper(DepthBasedMethod(), 'traditional'),
        UnifiedBaselineWrapper(RarityBasedMethod(), 'traditional'),
        UnifiedBaselineWrapper(SemanticBasedMethod(), 'traditional'),
        UnifiedBaselineWrapper(RandomMethod(), 'traditional'),
    ])
    
    # 2. 传统机器学习基线
    if SKLEARN_AVAILABLE:
        methods.extend([
            UnifiedBaselineWrapper(
                MLBasedMethod("Random Forest (Enhanced)", 
                             RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, class_weight='balanced'),
                             use_advanced_features=True), 'ml_enhanced'),
            UnifiedBaselineWrapper(
                MLBasedMethod("Logistic Regression (Enhanced)", 
                             LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000),
                             use_tfidf=True, use_advanced_features=True), 'ml_enhanced'),
        ])
    
    # 3. XGBoost基线
    if XGBOOST_AVAILABLE:
        n_positive = (df['label'] == 1).sum()
        n_negative = len(df) - n_positive
        scale_pos_weight = n_negative / n_positive if n_positive > 0 else 1.0
        
        methods.append(
            UnifiedBaselineWrapper(
                MLBasedMethod("XGBoost (Enhanced)", 
                             xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.05,
                                             random_state=42, scale_pos_weight=scale_pos_weight),
                             use_advanced_features=True), 'ml_enhanced')
        )
    
    # 4. 深度学习基线
    if PYTORCH_AVAILABLE:
        # MLP + Embedding基线
        mlp_baseline = create_mlp_baseline(
            model_params={'embedding_dim': 64, 'hidden_dim': 128, 'dropout': 0.3},
            training_params={'batch_size': 32, 'learning_rate': 1e-3, 'num_epochs': 30}
        )
        methods.append(UnifiedBaselineWrapper(mlp_baseline, 'deep_learning'))
        
        # Transformer基线
        transformer_baseline = create_transformer_baseline(
            model_params={'embedding_dim': 64, 'num_heads': 4, 'num_layers': 2, 'dropout': 0.3},
            training_params={'batch_size': 16, 'learning_rate': 5e-4, 'num_epochs': 40}
        )
        methods.append(UnifiedBaselineWrapper(transformer_baseline, 'deep_learning'))
    
    logger.info(f"将评估 {len(methods)} 种基线方法")
    
    # 评估所有方法
    all_results = {}
    
    for i, wrapper in enumerate(methods, 1):
        logger.info(f"\n[{i}/{len(methods)}] 开始评估: {wrapper.name}")
        try:
            result = evaluate_unified_method(wrapper, df, groups, k)
            all_results[wrapper.name] = result
            
            # 输出当前结果
            macro_hit_rate = result['macro_metrics']['attack_hit_rate']
            macro_f1 = result['macro_metrics']['f1']
            logger.info(f"✅ {wrapper.name} 完成: 宏平均命中率={macro_hit_rate:.3f}, 宏平均F1={macro_f1:.3f}")
            
        except Exception as e:
            logger.error(f"❌ {wrapper.name} 评估失败: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    # 保存详细结果
    results_file = os.path.join(output_dir, "comprehensive_results.json")
    with open(results_file, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    
    # 生成汇总表格
    summary_data = []
    for method_name, result in all_results.items():
        summary_data.append({
            'Method': method_name,
            'Type': result['method_type'],
            'Macro_Attack_Hit_Rate': f"{result['macro_metrics']['attack_hit_rate']:.3f}",
            'Macro_Precision': f"{result['macro_metrics']['precision']:.3f}",
            'Macro_Recall': f"{result['macro_metrics']['recall']:.3f}",
            'Macro_F1': f"{result['macro_metrics']['f1']:.3f}",
            'Micro_Attack_Hit_Rate': f"{result['micro_metrics']['attack_hit_rate']:.3f}",
            'Micro_F1': f"{result['micro_metrics']['f1']:.3f}",
            'Files_Evaluated': result['total_files']
        })
    
    # 按宏平均命中率排序
    summary_data.sort(key=lambda x: float(x['Macro_Attack_Hit_Rate']), reverse=True)
    
    summary_df = pd.DataFrame(summary_data)
    summary_file = os.path.join(output_dir, "comprehensive_summary.csv")
    summary_df.to_csv(summary_file, index=False)
    
    # 输出最终总结
    logger.info("\n" + "=" * 80)
    logger.info("综合基线对比完成")
    logger.info("=" * 80)
    logger.info("排名 (按宏平均攻击路径命中率):")
    
    for i, row in summary_df.iterrows():
        method_type = row['Type']
        type_icon = {"traditional": "📊", "ml_enhanced": "🤖", "deep_learning": "🧠"}.get(method_type, "❓")
        logger.info(f"{i+1:2d}. {type_icon} {row['Method']:25s} | 命中率: {row['Macro_Attack_Hit_Rate']} | F1: {row['Macro_F1']}")
    
    # 按类型分组显示最优结果
    logger.info("\n按方法类型最优结果:")
    type_groups = summary_df.groupby('Type')
    for method_type, group in type_groups:
        best_method = group.iloc[0]
        type_icon = {"traditional": "📊", "ml_enhanced": "🤖", "deep_learning": "🧠"}.get(method_type, "❓")
        logger.info(f"{type_icon} {method_type:15s}: {best_method['Method']:25s} | 命中率: {best_method['Macro_Attack_Hit_Rate']}")
    
    logger.info(f"\n详细结果保存在: {output_dir}")
    logger.info(f"汇总表格: {summary_file}")
    logger.info(f"详细数据: {results_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())