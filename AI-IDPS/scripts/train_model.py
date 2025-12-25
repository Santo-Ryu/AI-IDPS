"""
scripts/train_model.py
Module huấn luyện Isolation Forest học HÀNH VI, không học IP
Training pipeline với validation và metrics chi tiết
"""

import pandas as pd
import numpy as np
from typing import Dict, Tuple, Optional
from pathlib import Path
import sys
import yaml
import pickle
import json
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report, 
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.logger import get_module_logger
from src.core.data_processor import DataProcessor
from src.core.feature_engineer import FeatureEngineer


class ModelTrainer:
    """
    Trainer cho Isolation Forest - Behavior-based anomaly detection
    """
    
    def __init__(self, config: Dict):
        """Khởi tạo ModelTrainer"""
        self.config = config
        self.logger = get_module_logger("ModelTrainer")
        
        self.model = None
        self._init_model()
        
        self.training_history = {}
        self.evaluation_metrics = {}
        
        self.logger.info("="*80)
        self.logger.success("Khởi tạo ModelTrainer - Isolation Forest")
        self.logger.info("="*80)
    
    def _init_model(self):
        """Khởi tạo Isolation Forest với config"""
        try:
            mc = self.config['model']
            
            self.model = IsolationForest(
                contamination=mc['contamination'],
                n_estimators=mc['n_estimators'],
                max_samples=mc['max_samples'],
                random_state=mc['random_state'],
                n_jobs=mc['n_jobs'],
                verbose=0
            )
            
            self.logger.info(f"📊 Model: {mc['type']}")
            self.logger.info(f"  ↳ Contamination: {mc['contamination']}")
            self.logger.info(f"  ↳ N_estimators: {mc['n_estimators']}")
            self.logger.info(f"  ↳ Max_samples: {mc['max_samples']}")
            self.logger.info(f"  ↳ Random_state: {mc['random_state']}")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi init model: {str(e)}")
            raise
    
    def train(self, X_train: pd.DataFrame, y_train: Optional[pd.Series] = None) -> None:
        """
        Huấn luyện Isolation Forest (unsupervised)
        
        Args:
            X_train: Behavioral features
            y_train: Labels (optional, chỉ để validate)
        """
        try:
            self.logger.info("\n" + "="*80)
            self.logger.info("🚀 BẮT ĐẦU HUẤN LUYỆN MÔ HÌNH")
            self.logger.info("="*80)
            
            # Data info
            self.logger.info(f"\n📊 Training data info:")
            self.logger.info(f"  ↳ Shape: {X_train.shape}")
            self.logger.info(f"  ↳ Samples: {X_train.shape[0]:,}")
            self.logger.info(f"  ↳ Features: {X_train.shape[1]}")
            
            # Check missing values
            missing = X_train.isnull().sum().sum()
            if missing > 0:
                self.logger.warning(f"⚠️  Missing values: {missing}, filling với 0")
                X_train = X_train.fillna(0)
            
            # Verify no IP features
            self._verify_no_ip_features(X_train)
            
            # Training
            start_time = datetime.now()
            self.logger.info(f"\n⏰ Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.logger.info("🔄 Training Isolation Forest...")
            
            self.model.fit(X_train)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.logger.success(f"\n✅ Training hoàn tất trong {duration:.2f}s")
            
            # Predictions on training set
            predictions = self.model.predict(X_train)
            scores = self.model.decision_function(X_train)
            
            anomaly_count = (predictions == -1).sum()
            normal_count = (predictions == 1).sum()
            anomaly_ratio = anomaly_count / len(predictions)
            
            self.logger.info("\n📈 Training set predictions:")
            print(f"  {'Normal:':<20} {normal_count:>10,}  ({normal_count/len(predictions)*100:>5.1f}%)")
            print(f"  {'Anomaly:':<20} {anomaly_count:>10,}  ({anomaly_count/len(predictions)*100:>5.1f}%)")
            print(f"  {'Anomaly ratio:':<20} {anomaly_ratio:>10.2%}")
            
            # Score statistics
            self.logger.info("\n📊 Anomaly score statistics:")
            print(f"  {'Min score:':<20} {scores.min():>10.4f}")
            print(f"  {'Mean score:':<20} {scores.mean():>10.4f}")
            print(f"  {'Max score:':<20} {scores.max():>10.4f}")
            print(f"  {'Std score:':<20} {scores.std():>10.4f}")
            
            # Save training history
            self.training_history = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': duration,
                'n_samples': X_train.shape[0],
                'n_features': X_train.shape[1],
                'model_params': {
                    'contamination': self.model.contamination,
                    'n_estimators': self.model.n_estimators,
                    'max_samples': self.model.max_samples
                },
                'train_anomaly_ratio': float(anomaly_ratio),
                'score_statistics': {
                    'min': float(scores.min()),
                    'mean': float(scores.mean()),
                    'max': float(scores.max()),
                    'std': float(scores.std())
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi training: {str(e)}")
            raise
    
    # Kiểm tra không có IP features trong data, chỉ có behavioral features
    def _verify_no_ip_features(self, X: pd.DataFrame):
        """Verify không có IP features trong training data"""
        forbidden = ['src_ip', 'dst_ip', 'ip_count', 'ip_entropy', 'subnet']
        ip_features = [col for col in X.columns if any(f in col for f in forbidden)]
        
        if ip_features:
            self.logger.error(f"\n❌ CRITICAL: IP-based features detected!")
            self.logger.error(f"    Features: {ip_features}")
            raise ValueError("IP-based features không được phép trong training!")
        else:
            self.logger.success("✅ Verified: Chỉ có behavioral features")
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Dự đoán anomaly
        
        Returns:
            Array: -1 = anomaly, 1 = normal
        """
        try:
            if self.model is None:
                raise ValueError("Model chưa được train")
            
            if X.isnull().sum().sum() > 0:
                X = X.fillna(0)
            
            return self.model.predict(X)
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi predict: {str(e)}")
            raise
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Tính anomaly scores (càng âm càng bất thường)
        
        Returns:
            Array: anomaly scores
        """
        try:
            if self.model is None:
                raise ValueError("Model chưa được train")
            
            if X.isnull().sum().sum() > 0:
                X = X.fillna(0)
            
            return self.model.decision_function(X)
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi predict_proba: {str(e)}")
            raise
    
    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict:
        """
        Đánh giá model với ground truth labels
        
        Args:
            X_test: Test features
            y_test: True labels (0=normal, 1=anomaly hoặc 1=normal, -1=anomaly)
            
        Returns:
            Dict metrics
        """
        try:
            self.logger.info("\n" + "="*80)
            self.logger.info("📊 ĐÁNH GIÁ MÔ HÌNH")
            self.logger.info("="*80)
            
            # Predict
            y_pred = self.predict(X_test)
            scores = self.predict_proba(X_test)
            
            # Normalize labels to 0/1 (0=normal, 1=anomaly)
            y_test_binary = y_test.copy()
            if set(y_test.unique()).issubset({-1, 1}):
                # Convert -1/1 to 0/1
                y_test_binary = (y_test == -1).astype(int)
            
            y_pred_binary = (y_pred == -1).astype(int)
            
            # Metrics
            precision = precision_score(y_test_binary, y_pred_binary, zero_division=0)
            recall = recall_score(y_test_binary, y_pred_binary, zero_division=0)
            f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
            
            # AUC-ROC (sử dụng scores)
            try:
                auc = roc_auc_score(y_test_binary, -scores)  # Negative scores vì càng âm càng anomaly
            except:
                auc = 0.0
            
            # Confusion matrix
            cm = confusion_matrix(y_test_binary, y_pred_binary)
            tn, fp, fn, tp = cm.ravel()
            
            # Display metrics
            self.logger.info("\n📈 Performance Metrics:")
            print(f"  {'Precision:':<20} {precision:>10.4f}")
            print(f"  {'Recall:':<20} {recall:>10.4f}")
            print(f"  {'F1-Score:':<20} {f1:>10.4f}")
            print(f"  {'AUC-ROC:':<20} {auc:>10.4f}")
            
            self.logger.info("\n📊 Confusion Matrix:")
            print(f"  {'TN (True Normal):':<20} {tn:>10,}")
            print(f"  {'FP (False Positive):':<20} {fp:>10,}")
            print(f"  {'FN (False Negative):':<20} {fn:>10,}")
            print(f"  {'TP (True Positive):':<20} {tp:>10,}")
            
            # Accuracy
            accuracy = (tn + tp) / (tn + fp + fn + tp)
            print(f"\n  {'Accuracy:':<20} {accuracy:>10.2%}")
            
            # Classification report
            report = classification_report(
                y_test_binary, 
                y_pred_binary,
                target_names=['Normal', 'Anomaly'],
                zero_division=0
            )
            self.logger.info(f"\n📋 Classification Report:")
            print(report)
            
            # Save metrics
            self.evaluation_metrics = {
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'auc_roc': float(auc),
                'accuracy': float(accuracy),
                'confusion_matrix': {
                    'tn': int(tn),
                    'fp': int(fp),
                    'fn': int(fn),
                    'tp': int(tp)
                },
                'test_samples': len(X_test),
                'test_anomalies': int(y_test_binary.sum()),
                'predicted_anomalies': int(y_pred_binary.sum()),
                'classification_report': report
            }
            
            return self.evaluation_metrics
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi evaluate: {str(e)}")
            raise
    
    def plot_confusion_matrix(self, save_path: Optional[str] = None):
        """Vẽ confusion matrix"""
        try:
            if 'confusion_matrix' not in self.evaluation_metrics:
                self.logger.warning("Chưa có confusion matrix")
                return
            
            cm_dict = self.evaluation_metrics['confusion_matrix']
            cm = np.array([[cm_dict['tn'], cm_dict['fp']], 
                          [cm_dict['fn'], cm_dict['tp']]])
            
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                       xticklabels=['Normal', 'Anomaly'],
                       yticklabels=['Normal', 'Anomaly'],
                       cbar_kws={'label': 'Count'})
            
            plt.title('Confusion Matrix - Isolation Forest\n(Behavior-Based Detection)', 
                     fontsize=14, fontweight='bold')
            plt.ylabel('True Label', fontsize=12)
            plt.xlabel('Predicted Label', fontsize=12)
            
            # Add percentages
            total = cm.sum()
            for i in range(2):
                for j in range(2):
                    pct = cm[i,j] / total * 100
                    plt.text(j+0.5, i+0.7, f'({pct:.1f}%)', 
                            ha='center', va='center', fontsize=10, color='gray')
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"💾 Saved confusion matrix: {save_path}")
            
            plt.close()
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi plot confusion matrix: {str(e)}")
    
    def plot_anomaly_scores(self, X: pd.DataFrame, y_true: Optional[pd.Series] = None, 
                           save_path: Optional[str] = None):
        """Vẽ phân bố anomaly scores"""
        try:
            scores = self.predict_proba(X)
            
            fig, axes = plt.subplots(1, 2, figsize=(15, 5))
            
            # Plot 1: Overall distribution
            axes[0].hist(scores, bins=50, alpha=0.7, color='blue', edgecolor='black')
            axes[0].axvline(x=0, color='red', linestyle='--', linewidth=2, label='Decision Boundary')
            axes[0].set_xlabel('Anomaly Score', fontsize=12)
            axes[0].set_ylabel('Frequency', fontsize=12)
            axes[0].set_title('Distribution of Anomaly Scores', fontsize=14, fontweight='bold')
            axes[0].legend()
            axes[0].grid(True, alpha=0.3)
            
            # Plot 2: Separated by true label (if available)
            if y_true is not None:
                y_binary = (y_true == -1).astype(int) if set(y_true.unique()).issubset({-1, 1}) else y_true
                
                normal_scores = scores[y_binary == 0]
                anomaly_scores = scores[y_binary == 1]
                
                axes[1].hist(normal_scores, bins=30, alpha=0.6, color='green', 
                           label='Normal', edgecolor='black')
                axes[1].hist(anomaly_scores, bins=30, alpha=0.6, color='red', 
                           label='Anomaly', edgecolor='black')
                axes[1].axvline(x=0, color='black', linestyle='--', linewidth=2, 
                              label='Decision Boundary')
                axes[1].set_xlabel('Anomaly Score', fontsize=12)
                axes[1].set_ylabel('Frequency', fontsize=12)
                axes[1].set_title('Scores by True Label', fontsize=14, fontweight='bold')
                axes[1].legend()
                axes[1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"💾 Saved score distribution: {save_path}")
            
            plt.close()
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi plot scores: {str(e)}")
    
    def save_model(self, filepath: str):
        """Lưu model và metadata"""
        try:
            self.logger.info(f"\n💾 Lưu model vào: {filepath}")
            
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            # Save model
            with open(filepath, 'wb') as f:
                pickle.dump(self.model, f)
            
            self.logger.success(f"✅ Đã lưu model")
            
            # Save metadata
            metadata_path = filepath.replace('.pkl', '_metadata.json')
            metadata = {
                'model_type': 'IsolationForest',
                'training_history': self.training_history,
                'evaluation_metrics': self.evaluation_metrics,
                'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'note': 'Behavior-based model - NO IP features used'
            }
            
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📄 Đã lưu metadata: {metadata_path}")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi lưu model: {str(e)}")
            raise
    
    @staticmethod
    def load_model(filepath: str):
        """Load model từ file"""
        with open(filepath, 'rb') as f:
            return pickle.load(f)


def main():
    """Pipeline huấn luyện đầy đủ"""
    
    print("\n" + "="*80)
    print("🚀 AI-IDPS TRAINING PIPELINE - BEHAVIOR-BASED ANOMALY DETECTION")
    print("="*80 + "\n")
    
    # Load config
    config_path = 'config/config.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    logger = get_module_logger("Pipeline")
    
    # ========== STEP 1: DATA PROCESSING ==========
    logger.info("📦 STEP 1: DATA PROCESSING")
    processor = DataProcessor(config)
    df = processor.load_logs(config['data']['training_logs'])
    processor.validate_data()
    df_cleaned = processor.clean_data()
    processor.save_processed_data(config['data']['cleaned_logs'])
    processor.print_summary()
    
    # ========== STEP 2: FEATURE ENGINEERING ==========
    logger.info("\n🔧 STEP 2: FEATURE ENGINEERING")
    engineer = FeatureEngineer(config)
    df_features = engineer.create_features(df_cleaned)
    df_encoded = engineer.encode_features(df_features, fit=True)
    df_selected = engineer.select_features(df_encoded)
    df_scaled = engineer.scale_features(df_selected, fit=True)
    engineer.save_engineer(config['paths']['engineer_path'])
    engineer.print_feature_summary()
    
    # ========== STEP 3: MODEL TRAINING ==========
    logger.info("\n🤖 STEP 3: MODEL TRAINING")
    trainer = ModelTrainer(config)
    trainer.train(df_scaled)
    
    # ========== STEP 4: EVALUATION (if labels available) ==========
    if 'action' in df_cleaned.columns:
        logger.info("\n📊 STEP 4: MODEL EVALUATION")
        
        # Tạo labels từ action (block=anomaly)
        y_true = (df_cleaned['action'] == 'block').astype(int)
        
        trainer.evaluate(df_scaled, y_true)
        
        # Plot visualizations
        output_dir = Path(config['paths']['output_dir'])
        trainer.plot_confusion_matrix(str(output_dir / 'confusion_matrix.png'))
        trainer.plot_anomaly_scores(df_scaled, y_true, str(output_dir / 'anomaly_scores.png'))
    
    # ========== STEP 5: SAVE MODEL ==========
    logger.info("\n💾 STEP 5: SAVE MODEL")
    trainer.save_model(config['paths']['model_path'])
    
    # ========== SUMMARY ==========
    print("\n" + "="*80)
    logger.success("✅ TRAINING PIPELINE HOÀN TẤT!")
    print("="*80)
    
    print(f"\n📊 Training Summary:")
    print(f"  {'Model type:':<30} Isolation Forest (Behavior-Based)")
    print(f"  {'Training samples:':<30} {len(df_scaled):,}")
    print(f"  {'Features:':<30} {len(engineer.feature_columns)}")
    print(f"  {'Model path:':<30} {config['paths']['model_path']}")
    print(f"  {'Engineer path:':<30} {config['paths']['engineer_path']}")
    
    if trainer.evaluation_metrics:
        print(f"\n📈 Performance:")
        print(f"  {'Precision:':<30} {trainer.evaluation_metrics['precision']:.4f}")
        print(f"  {'Recall:':<30} {trainer.evaluation_metrics['recall']:.4f}")
        print(f"  {'F1-Score:':<30} {trainer.evaluation_metrics['f1_score']:.4f}")
    
    print("\n" + "="*80 + "\n")


if __name__ == '__main__':
    main()
