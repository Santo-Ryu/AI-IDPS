"""
src/core/feature_engineer.py
Module tạo đặc trưng HÀNH VI (behavior) từ logs pfSense
KHÔNG sử dụng IP addresses làm features - chỉ học patterns
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional
from pathlib import Path
import sys
from sklearn.preprocessing import LabelEncoder, StandardScaler
from collections import Counter
import pickle

sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.logger import get_module_logger


class FeatureEngineer:
    """
    Class tạo đặc trưng HÀNH VI cho Isolation Forest
    Focus: Network behavior patterns, NOT IP identifiers
    """
    
    # Features BỊ CẤM - không được đưa vào model
    FORBIDDEN_FEATURES = [
        'src_ip', 'dst_ip',              # IP identifiers
        'src_ip_count', 'dst_ip_count',   # IP frequency
        'src_unique_dst', 'src_block_ratio', # IP statistics
        'same_subnet', 'src_ip_entropy', 'dst_ip_entropy'  # IP-based
    ]
    
    def __init__(self, config: Dict):
        """Khởi tạo FeatureEngineer"""
        self.config = config
        self.logger = get_module_logger("FeatureEngineer")
        
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_columns = []
        
        self.logger.info("="*80)
        self.logger.success("Khởi tạo FeatureEngineer - Behavior-Only Mode")
        self.logger.info("="*80)
        self.logger.warning("🚫 IP-based features bị VÔ HIỆU HÓA - Chỉ học hành vi!")
    
    def create_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Tạo TẤT CẢ behavioral features
        
        Args:
            df: DataFrame logs đã clean
            
        Returns:
            DataFrame với behavioral features
        """
        try:
            self.logger.info("\n🔧 Bắt đầu tạo BEHAVIORAL FEATURES...")
            
            df_features = df.copy()
            
            # 1. Time-based behaviors
            df_features = self._create_temporal_features(df_features)
            
            # 2. Port behaviors  
            df_features = self._create_port_behavior_features(df_features)
            
            # 3. Protocol behaviors
            df_features = self._create_protocol_behavior_features(df_features)
            
            # 4. Packet behaviors
            df_features = self._create_packet_behavior_features(df_features)
            
            # 5. Connection behaviors
            df_features = self._create_connection_behavior_features(df_features)
            
            # 6. TCP/UDP specific behaviors
            df_features = self._create_transport_behavior_features(df_features)
            
            new_features = len(df_features.columns) - len(df.columns)
            self.logger.success(f"✅ Đã tạo {new_features} behavioral features")
            
            # Kiểm tra không có forbidden features
            self._verify_no_forbidden_features(df_features)
            
            return df_features
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi tạo features: {str(e)}")
            raise
    
    def _create_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Tạo features về thời gian - PATTERNS, không phải timestamps"""
        self.logger.info("  ↳ Temporal behavior features...")
        
        if '@timestamp' not in df.columns:
            return df
        
        df['timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        
        # Time-of-day patterns
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Cyclical encoding (sine/cosine) - better for ML
        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        # Activity patterns
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hour'] = ((df['hour'] >= 8) & (df['hour'] <= 17)).astype(int)
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        df['is_peak_hour'] = df['hour'].isin([9, 10, 11, 14, 15, 16]).astype(int)
        
        self.logger.info("    • Created: hour_sin/cos, day_sin/cos, time_patterns")
        
        return df
    
    def _create_port_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Port behavior patterns - không quan tâm IP nào dùng"""
        self.logger.info("  ↳ Port behavior features...")
        
        # Port categories
        df['src_is_wellknown'] = (df['src_port'] <= 1023).astype(int)
        df['dst_is_wellknown'] = (df['dst_port'] <= 1023).astype(int)
        df['src_is_registered'] = ((df['src_port'] > 1023) & (df['src_port'] <= 49151)).astype(int)
        df['dst_is_registered'] = ((df['dst_port'] > 1023) & (df['dst_port'] <= 49151)).astype(int)
        df['src_is_dynamic'] = (df['src_port'] > 49151).astype(int)
        df['dst_is_dynamic'] = (df['dst_port'] > 49151).astype(int)
        
        # High-risk ports (commonly attacked)
        high_risk_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 3306, 5432, 1433]
        df['dst_is_high_risk'] = df['dst_port'].isin(high_risk_ports).astype(int)
        
        # Port behaviors
        df['port_diff'] = abs(df['dst_port'] - df['src_port'])
        df['port_range_span'] = df[['src_port', 'dst_port']].max(axis=1) - df[['src_port', 'dst_port']].min(axis=1)
        
        # Port scanning behavior (sequential ports)
        df['is_sequential_port'] = ((df['src_port'] % 100 == 0) | (df['dst_port'] % 100 == 0)).astype(int)
        
        # Common service ports
        web_ports = [80, 443, 8080, 8443]
        db_ports = [3306, 5432, 1433, 27017]
        df['dst_is_web_service'] = df['dst_port'].isin(web_ports).astype(int)
        df['dst_is_db_service'] = df['dst_port'].isin(db_ports).astype(int)
        
        self.logger.info("    • Created: port_categories, risk_levels, behaviors")
        
        return df
    
    def _create_protocol_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Protocol behavior patterns"""
        self.logger.info("  ↳ Protocol behavior features...")
        
        if 'proto_name' not in df.columns:
            return df
        
        # Protocol one-hot
        common_protocols = ['tcp', 'udp', 'icmp']
        for proto in common_protocols:
            df[f'is_{proto}'] = (df['proto_name'] == proto).astype(int)
        
        # Protocol + action combinations (behavioral patterns)
        if 'action' in df.columns:
            df['tcp_blocked'] = ((df['proto_name'] == 'tcp') & (df['action'] == 'block')).astype(int)
            df['udp_blocked'] = ((df['proto_name'] == 'udp') & (df['action'] == 'block')).astype(int)
            df['icmp_blocked'] = ((df['proto_name'] == 'icmp') & (df['action'] == 'block')).astype(int)
        
        # Direction + protocol patterns
        if 'dir' in df.columns:
            df['tcp_inbound'] = ((df['proto_name'] == 'tcp') & (df['dir'] == 'in')).astype(int)
            df['tcp_outbound'] = ((df['proto_name'] == 'tcp') & (df['dir'] == 'out')).astype(int)
            df['udp_inbound'] = ((df['proto_name'] == 'udp') & (df['dir'] == 'in')).astype(int)
        
        self.logger.info("    • Created: protocol_types, proto_action_combos, directions")
        
        return df
    
    def _create_packet_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Packet size/TTL behaviors"""
        self.logger.info("  ↳ Packet behavior features...")
        
        # Packet size behaviors
        if 'length' in df.columns:
            df['packet_size_tiny'] = (df['length'] <= 64).astype(int)
            df['packet_size_small'] = ((df['length'] > 64) & (df['length'] <= 512)).astype(int)
            df['packet_size_medium'] = ((df['length'] > 512) & (df['length'] <= 1024)).astype(int)
            df['packet_size_large'] = (df['length'] > 1024).astype(int)
            
            # Normalized packet size
            df['packet_size_norm'] = df['length'] / 1500  # MTU
        
        # TTL behaviors (OS fingerprinting patterns)
        if 'ttl' in df.columns:
            df['ttl_is_linux'] = (df['ttl'] == 64).astype(int)
            df['ttl_is_windows'] = ((df['ttl'] == 128) | (df['ttl'] == 127)).astype(int)
            df['ttl_is_suspicious'] = ((df['ttl'] < 30) | (df['ttl'] > 200)).astype(int)
            df['ttl_normalized'] = df['ttl'] / 255
        
        # Data length ratio
        if 'data_length' in df.columns and 'length' in df.columns:
            df['data_ratio'] = df['data_length'] / (df['length'] + 1)  # Avoid div by zero
        
        self.logger.info("    • Created: packet_sizes, ttl_patterns, ratios")
        
        return df
    
    def _create_connection_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Connection-level behaviors (action, direction patterns)"""
        self.logger.info("  ↳ Connection behavior features...")
        
        # Action behaviors
        if 'action' in df.columns:
            df['is_blocked'] = (df['action'] == 'block').astype(int)
            df['is_passed'] = (df['action'] == 'pass').astype(int)
        
        # Direction behaviors
        if 'dir' in df.columns:
            df['is_inbound'] = (df['dir'] == 'in').astype(int)
            df['is_outbound'] = (df['dir'] == 'out').astype(int)
        
        # Action + Direction combinations
        if 'action' in df.columns and 'dir' in df.columns:
            df['inbound_blocked'] = ((df['dir'] == 'in') & (df['action'] == 'block')).astype(int)
            df['outbound_blocked'] = ((df['dir'] == 'out') & (df['action'] == 'block')).astype(int)
        
        # Reason patterns
        if 'reason' in df.columns:
            df['reason_is_match'] = (df['reason'] == 'match').astype(int)
        
        self.logger.info("    • Created: action_types, directions, combinations")
        
        return df
    
    def _create_transport_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """TCP/UDP specific behavior features"""
        self.logger.info("  ↳ Transport layer behavior features...")
        
        # TCP flags behaviors
        if 'tcp_flags' in df.columns:
            # Xử lý tcp_flags đã được normalize thành string (vd: "S,A" hoặc "S")
            tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']
            for flag in tcp_flags:
                # Check nếu flag có trong string (hỗ trợ cả "S" và "S,A,F")
                df[f'tcp_flag_{flag.lower()}'] = df['tcp_flags'].astype(str).str.contains(
                    flag, na=False, regex=False
                ).astype(int)
            
            # Common flag combinations (attack patterns)
            df['tcp_syn_only'] = (df['tcp_flags'].astype(str) == 'S').astype(int)  # SYN scan
            df['tcp_fin_only'] = (df['tcp_flags'].astype(str) == 'F').astype(int)  # FIN scan
            df['tcp_null_scan'] = (df['tcp_flags'].astype(str).isin(['', 'nan', 'None'])).astype(int)  # NULL scan
            
            # XMAS scan: chứa cả F, P, U
            df['tcp_xmas_scan'] = (
                df['tcp_flags'].astype(str).str.contains('F', na=False) & 
                df['tcp_flags'].astype(str).str.contains('P', na=False) & 
                df['tcp_flags'].astype(str).str.contains('U', na=False)
            ).astype(int)
        
        # Window size behaviors (đã được normalize thành scalar)
        if 'window' in df.columns:
            df['window'] = pd.to_numeric(df['window'], errors='coerce').fillna(0)
            df['window_is_zero'] = (df['window'] == 0).astype(int)
            df['window_is_max'] = (df['window'] >= 65535).astype(int)
        
        self.logger.info("    • Created: tcp_flags, flag_combos, window_patterns")
        
        return df
    
    def _verify_no_forbidden_features(self, df: pd.DataFrame):
        """Kiểm tra không có IP-based features"""
        forbidden_found = [f for f in self.FORBIDDEN_FEATURES if f in df.columns]
        
        if forbidden_found:
            self.logger.warning(f"\n❌ PHÁT HIỆN FORBIDDEN FEATURES: {forbidden_found}")
            self.logger.warning("    Các features này sẽ KHÔNG được đưa vào model!")
        else:
            self.logger.success("✅ Verified: Không có IP-based features")
    
    def encode_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Encode categorical features"""
        try:
            self.logger.info("\n🔤 Encode categorical features...")
            
            df_encoded = df.copy()
            
            categorical_cols = ['action', 'proto_name', 'dir', 'reason']
            categorical_cols = [c for c in categorical_cols if c in df_encoded.columns]
            
            for col in categorical_cols:
                if fit:
                    self.label_encoders[col] = LabelEncoder()
                    df_encoded[f'{col}_encoded'] = self.label_encoders[col].fit_transform(
                        df_encoded[col].astype(str).fillna('unknown')
                    )
                    self.logger.info(f"  ↳ Encoded '{col}': {len(self.label_encoders[col].classes_)} classes")
                else:
                    if col in self.label_encoders:
                        df_encoded[f'{col}_encoded'] = df_encoded[col].astype(str).fillna('unknown').apply(
                            lambda x: self.label_encoders[col].transform([x])[0] 
                            if x in self.label_encoders[col].classes_ else -1
                        )
            
            self.logger.success(f"✅ Encoded {len(categorical_cols)} features")
            
            return df_encoded
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi encode: {str(e)}")
            raise
    
    def select_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Chọn FINAL behavioral features cho model"""
        try:
            self.logger.info("\n🎯 Chọn final features cho model...")
            
            # BEHAVIORAL FEATURES ONLY
            behavioral_features = [
                # Temporal
                'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
                'is_weekend', 'is_business_hour', 'is_night', 'is_peak_hour',
                
                # Port behaviors
                'src_port', 'dst_port',
                'src_is_wellknown', 'dst_is_wellknown',
                'src_is_registered', 'dst_is_registered',
                'src_is_dynamic', 'dst_is_dynamic',
                'dst_is_high_risk', 'port_diff', 'port_range_span',
                'is_sequential_port', 'dst_is_web_service', 'dst_is_db_service',
                
                # Protocol behaviors
                'is_tcp', 'is_udp', 'is_icmp',
                'tcp_blocked', 'udp_blocked', 'icmp_blocked',
                'tcp_inbound', 'tcp_outbound', 'udp_inbound',
                
                # Packet behaviors
                'length', 'ttl',
                'packet_size_tiny', 'packet_size_small', 'packet_size_medium', 'packet_size_large',
                'packet_size_norm', 'ttl_is_linux', 'ttl_is_windows',
                'ttl_is_suspicious', 'ttl_normalized', 'data_ratio',
                
                # Connection behaviors
                'is_blocked', 'is_passed', 'is_inbound', 'is_outbound',
                'inbound_blocked', 'outbound_blocked', 'reason_is_match',
                
                # Transport behaviors
                'tcp_flag_s', 'tcp_flag_a', 'tcp_flag_f', 'tcp_flag_r',
                'tcp_flag_p', 'tcp_flag_u',
                'tcp_syn_only', 'tcp_fin_only', 'tcp_null_scan', 'tcp_xmas_scan',
                'window_is_zero', 'window_is_max',
                
                # Encoded
                'action_encoded', 'proto_name_encoded', 'dir_encoded'
            ]
            
            # Chỉ giữ features tồn tại
            self.feature_columns = [f for f in behavioral_features if f in df.columns]
            
            # VERIFY: Không có forbidden features
            forbidden_in_final = [f for f in self.FORBIDDEN_FEATURES if f in self.feature_columns]
            if forbidden_in_final:
                self.logger.error(f"❌ CRITICAL: Forbidden features leaked: {forbidden_in_final}")
                self.feature_columns = [f for f in self.feature_columns if f not in self.FORBIDDEN_FEATURES]
            
            df_selected = df[self.feature_columns].copy()
            df_selected = df_selected.fillna(0)
            
            self.logger.success(f"✅ Selected {len(self.feature_columns)} BEHAVIORAL features")
            self.logger.info(f"    Feature categories: temporal, port, protocol, packet, connection, transport")
            
            return df_selected
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi select features: {str(e)}")
            raise
    
    def scale_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Scale features về cùng range"""
        try:
            self.logger.info("\n⚖️  Scale features...")
            
            if fit:
                scaled_data = self.scaler.fit_transform(df)
                self.logger.info("  ↳ Fitted scaler với training data")
            else:
                scaled_data = self.scaler.transform(df)
                self.logger.info("  ↳ Transformed với scaler đã fit")
            
            df_scaled = pd.DataFrame(scaled_data, columns=df.columns, index=df.index)
            
            self.logger.success("✅ Scaling hoàn tất")
            
            return df_scaled
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi scale: {str(e)}")
            raise
    
    def save_engineer(self, filepath: str):
        """Lưu FeatureEngineer object"""
        try:
            self.logger.info(f"\n💾 Lưu FeatureEngineer vào: {filepath}")
            
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'wb') as f:
                pickle.dump(self, f)
            
            self.logger.success(f"✅ Đã lưu FeatureEngineer")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi lưu: {str(e)}")
            raise
    
    @staticmethod
    def load_engineer(filepath: str):
        """Load FeatureEngineer từ file"""
        with open(filepath, 'rb') as f:
            return pickle.load(f)
    
    def print_feature_summary(self):
        """In tóm tắt features đã tạo"""
        self.logger.info("\n" + "="*80)
        self.logger.info("🎯 FEATURE SUMMARY")
        self.logger.info("="*80)
        
        print(f"\n{'Total features selected:':<35} {len(self.feature_columns):>10}")
        
        categories = {
            'Temporal': ['hour', 'day', 'weekend', 'business', 'night', 'peak'],
            'Port': ['port', 'wellknown', 'registered', 'dynamic', 'risk', 'sequential'],
            'Protocol': ['tcp', 'udp', 'icmp', 'proto'],
            'Packet': ['packet', 'length', 'ttl', 'size', 'data'],
            'Connection': ['blocked', 'passed', 'inbound', 'outbound'],
            'Transport': ['flag', 'window', 'scan']
        }
        
        print(f"\n{'Feature Categories:':<35}")
        for cat, keywords in categories.items():
            count = sum(1 for f in self.feature_columns if any(k in f for k in keywords))
            if count > 0:
                print(f"  {cat:<33} {count:>10}")
        
        print("\n" + "="*80 + "\n")


if __name__ == '__main__':
    import yaml
    
    with open('config/config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    df_cleaned = pd.read_pickle(config['data']['cleaned_logs'])
    
    engineer = FeatureEngineer(config)
    df_features = engineer.create_features(df_cleaned)
    df_encoded = engineer.encode_features(df_features, fit=True)
    df_selected = engineer.select_features(df_encoded)
    df_scaled = engineer.scale_features(df_selected, fit=True)
    
    engineer.save_engineer(config['paths']['engineer_path'])
    engineer.print_feature_summary()
