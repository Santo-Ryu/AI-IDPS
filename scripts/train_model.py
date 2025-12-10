"""
Train Model Script
Train and save Isolation Forest model
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
import logging
from src.data_processor import DataProcessor
from src.feature_engineer import FeatureEngineer
from src.anomaly_detector import AnomalyDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config():
    """Load configuration"""
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)


def main():
    """Main training pipeline"""
    logger.info("=" * 60)
    logger.info("Starting Model Training Pipeline")
    logger.info("=" * 60)
    
    # Load configuration
    config = load_config()
    
    # Get data path
    data_path = config['data']['sample_logs']
    if not os.path.exists(data_path):
        logger.error(f"Data file not found: {data_path}")
        logger.info("Please run generate_sample_data.py first")
        return
    
    logger.info(f"\n📁 Loading data from: {data_path}")
    
    # Initialize modules
    processor = DataProcessor(config)
    feature_engineer = FeatureEngineer(config)
    detector = AnomalyDetector(config)
    
    # Step 1: Process data
    logger.info("\n" + "=" * 60)
    logger.info("STEP 1: Data Processing")
    logger.info("=" * 60)
    df = processor.process(data_path)
    logger.info(f"✅ Processed {len(df)} log entries")
    
    # Step 2: Feature engineering
    logger.info("\n" + "=" * 60)
    logger.info("STEP 2: Feature Engineering")
    logger.info("=" * 60)
    features_df = feature_engineer.engineer_features(df)
    logger.info(f"✅ Engineered {len(features_df.columns)} features")
    logger.info(f"Features: {list(features_df.columns)}")
    
    # Save processed features
    output_path = config['data']['processed_features']
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    features_df.to_csv(output_path, index=False)
    logger.info(f"✅ Saved processed features to: {output_path}")
    
    # Step 3: Train model
    logger.info("\n" + "=" * 60)
    logger.info("STEP 3: Model Training")
    logger.info("=" * 60)
    detector.train(features_df)
    logger.info("✅ Model training complete")
    
    # Step 4: Evaluate on training data
    logger.info("\n" + "=" * 60)
    logger.info("STEP 4: Model Evaluation")
    logger.info("=" * 60)
    metrics = detector.evaluate(features_df)
    
    # Step 5: Save model
    logger.info("\n" + "=" * 60)
    logger.info("STEP 5: Saving Model")
    logger.info("=" * 60)
    
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    detector.save_model()
    logger.info("✅ Model saved successfully")
    
    # Test predictions
    logger.info("\n" + "=" * 60)
    logger.info("STEP 6: Testing Predictions")
    logger.info("=" * 60)
    
    results = detector.detect_anomalies(features_df)
    anomalous_ips = detector.get_anomalous_ips(results)
    
    logger.info(f"\n📊 Detection Results:")
    logger.info(f"   Total logs analyzed: {len(results)}")
    logger.info(f"   Anomalies detected: {results['is_anomaly'].sum()}")
    logger.info(f"   High-risk events: {results['is_high_risk'].sum()}")
    logger.info(f"   Unique anomalous IPs: {len(anomalous_ips)}")
    
    if anomalous_ips:
        logger.info(f"\n🚨 Top 5 Anomalous IPs:")
        for i, ip_info in enumerate(anomalous_ips[:5], 1):
            logger.info(f"   {i}. {ip_info['src_ip']}")
            logger.info(f"      Score: {ip_info['avg_score']:.4f}")
            logger.info(f"      Count: {ip_info['anomaly_count']}")
            logger.info(f"      Risk: {ip_info['risk_level']}")
    
    logger.info("\n" + "=" * 60)
    logger.info("✅ Training Pipeline Complete!")
    logger.info("=" * 60)
    logger.info("\nYou can now run: python main.py")


if __name__ == '__main__':
    main()
