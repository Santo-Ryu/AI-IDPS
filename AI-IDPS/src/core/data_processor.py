"""
src/core/data_processor.py
Module xử lý và làm sạch dữ liệu logs từ pfSense firewall
Tập trung vào behavior patterns, không phụ thuộc vào IP identifiers
"""

import json
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Union
from pathlib import Path
import sys
import pickle
from datetime import datetime

sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.logger import get_module_logger


class DataProcessor:
    """
    Class xử lý dữ liệu logs từ firewall pfSense
    Tập trung vào behavioral features, loại bỏ IP-based features
    """
    
    def __init__(self, config: Dict):
        """
        Khởi tạo DataProcessor
        
        Args:
            config: Dictionary chứa cấu hình từ config.yaml
        """
        self.config = config
        self.logger = get_module_logger("DataProcessor")
        self.df = None
        self.stats = {}
        
        self.logger.info("="*80)
        self.logger.success("Khởi tạo DataProcessor - Behavior-Focused Mode")
        self.logger.info("="*80)
    
    
    def load_logs(self, filepath: str) -> pd.DataFrame:
        """
        Load dữ liệu logs từ file JSON hoặc JSON Lines (NDJSON)
        
        Args:
            filepath: Đường dẫn đến file logs (.json hoặc .jsonl)
            
        Returns:
            DataFrame chứa dữ liệu logs
        """
        try:
            self.logger.info(f"📂 Đang load logs từ: {filepath}")
            
            filepath = Path(filepath)
            if not filepath.exists():
                raise FileNotFoundError(f"❌ Không tìm thấy file: {filepath}")
            
            data = []
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:  # Bỏ qua dòng trống
                        continue
                    try:
                        json_obj = json.loads(line)
                        data.append(json_obj)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"❌ Lỗi parse JSON ở dòng {line_num}: {e}")
                        self.logger.error(f"   Nội dung dòng (200 ký tự đầu): {line[:200]}...")
                        raise
            
            if not data:
                raise ValueError("File log rỗng hoặc không chứa dữ liệu JSON hợp lệ")
            
            # Tạo DataFrame
            self.df = pd.DataFrame(data)
            
            # Hỗ trợ cũ: nếu là JSON chuẩn (một list lớn), vẫn hoạt động
            # Nhưng ưu tiên JSON Lines như trên
            
            self.logger.success(f"✅ Load thành công {len(self.df):,} bản ghi logs")
            self.stats['total_records'] = len(self.df)
            
            # Hiển thị sample
            self._display_sample()
            
            return self.df
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi khi load logs: {str(e)}")
            raise
    
    # Flatten Elasticsearch hit nếu cần
    def _flatten_elasticsearch_hit(self, hit: Dict) -> Dict:
        """
        Flatten Elasticsearch hit document
        
        Args:
            hit: Document từ Elasticsearch
            
        Returns:
            Flat dictionary
        """
        record = {}
        
        # Lấy _source hoặc fields
        if '_source' in hit:
            source = hit['_source']
        elif 'fields' in hit:
            source = {k: v[0] if isinstance(v, list) and len(v) == 1 else v 
                     for k, v in hit['fields'].items()}
        else:
            source = hit
        
        # Flatten nested fields
        for key, value in source.items():
            if isinstance(value, list) and len(value) == 1:
                record[key] = value[0]
            elif isinstance(value, list) and len(value) == 0:
                record[key] = None
            else:
                record[key] = value
        
        return record
    
    def _display_sample(self):
        """Hiển thị sample data"""
        if self.df is not None and len(self.df) > 0:
            self.logger.info("\n📊 Sample data (5 bản ghi đầu):")
            sample_cols = ['@timestamp', 'action', 'src_ip', 'dst_ip', 'src_port', 
                          'dst_port', 'proto_name', 'length']
            available_cols = [c for c in sample_cols if c in self.df.columns]
            
            if available_cols:
                print(self.df[available_cols].head().to_string(index=False))
    
    def validate_data(self) -> bool:
        """
        Kiểm tra tính hợp lệ của dữ liệu
        """
        try:
            self.logger.info("\n🔍 Bắt đầu validate dữ liệu...")
            
            if self.df is None or len(self.df) == 0:
                self.logger.error("❌ DataFrame rỗng")
                return False
            
            # Các trường bắt buộc cho behavior analysis
            required_fields = {
                'behavioral': ['src_port', 'dst_port', 'proto_name', 'action', 'dir'],
                'temporal': ['@timestamp'],
                'packet': ['length', 'ttl'],
                'context': ['src_ip', 'dst_ip']  # Chỉ dùng để thống kê, không train
            }
            
            missing_critical = []
            for category, fields in required_fields.items():
                for field in fields:
                    if field not in self.df.columns:
                        missing_critical.append(f"{field} ({category})")
            
            if missing_critical:
                self.logger.warning(f"⚠️  Thiếu trường: {', '.join(missing_critical)}")
                # Tạo trường thiếu với giá trị mặc định
                for field in missing_critical:
                    field_name = field.split(' ')[0]
                    self.df[field_name] = None
            
            # Thống kê null values
            null_counts = self.df.isnull().sum()
            if null_counts.sum() > 0:
                self.logger.warning("\n⚠️  Null values detected:")
                print(null_counts[null_counts > 0].to_string())
            
            self.logger.success("✅ Validate hoàn tất")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi validate: {str(e)}")
            return False


    def _normalize_list_columns(self):
        """
        Normalize các cột chứa list về scalar hoặc string.
        Xử lý đặc thù Elasticsearch array fields.
        
        Logic:
        - [] → None
        - [single_value] → single_value  
        - [val1, val2, ...] → "val1,val2,..." (join string)
        - scalar → scalar (không đổi)
        """
        list_columns = []
        
        # Phát hiện các cột chứa list
        for col in self.df.columns:
            # Check nếu bất kỳ giá trị nào trong cột là list
            if self.df[col].apply(lambda x: isinstance(x, list)).any():
                list_columns.append(col)
        
        if not list_columns:
            self.logger.info("  ↳ Không có cột list nào cần normalize")
            return
        
        self.logger.info(f"  ↳ Phát hiện {len(list_columns)} cột chứa list:")
        self.logger.info(f"    {', '.join(list_columns)}")
        
        for col in list_columns:
            def extract_value(x):
                """Trích xuất giá trị từ list hoặc giữ nguyên scalar"""
                if isinstance(x, list):
                    if len(x) == 0:
                        return None  # Empty list → None
                    elif len(x) == 1:
                        return x[0]  # Single value → extract
                    else:
                        # Multiple values → join thành string
                        # Dùng str() để đảm bảo tất cả elements đều convert được
                        return ','.join(str(item) for item in x)
                return x  # Giữ nguyên scalar
            
            self.df[col] = self.df[col].apply(extract_value)
            self.logger.debug(f"    • Normalized: {col}")
        
        self.logger.success(f"  ↳ ✅ Đã normalize {len(list_columns)} cột")
    
    def clean_data(self) -> pd.DataFrame:
        """
        Làm sạch dữ liệu: normalize lists, xử lý missing, duplicates, outliers
        
        Returns:
            pd.DataFrame: Dữ liệu đã được làm sạch
        """
        try:
            self.logger.info("\n🧹 Bắt đầu làm sạch dữ liệu...")
            initial_count = len(self.df)
            
            # ✅ BƯỚC 1: Normalize list columns TRƯỚC (critical!)
            self._normalize_list_columns()
            
            # ✅ BƯỚC 2: Xóa duplicates (giờ đã an toàn)
            dup_count = self.df.duplicated().sum()
            if dup_count > 0:
                self.df = self.df.drop_duplicates()
                self.logger.info(f"  ↳ Đã xóa {dup_count:,} bản ghi trùng lặp")
            else:
                self.logger.info(f"  ↳ Không có bản ghi trùng lặp")
            
            # ✅ BƯỚC 3: Chuyển đổi kiểu dữ liệu
            self._convert_data_types()
            
            # ✅ BƯỚC 4: Xử lý missing values
            self._handle_missing_values()
            
            # ✅ BƯỚC 5: Xử lý outliers
            self._handle_outliers()
            
            # ✅ BƯỚC 6: Chuẩn hóa giá trị
            self._normalize_values()
            
            final_count = len(self.df)
            removed = initial_count - final_count
            
            self.stats['records_removed'] = removed
            self.stats['final_records'] = final_count
            
            self.logger.success(f"✅ Làm sạch hoàn tất: {initial_count:,} → {final_count:,} "
                            f"({removed:,} bị loại)")
            
            return self.df
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi làm sạch: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            raise
    
    def _convert_data_types(self):
        """Chuyển đổi kiểu dữ liệu"""
        self.logger.info("  ↳ Chuyển đổi kiểu dữ liệu...")
        
        # Numeric fields
        numeric_fields = ['src_port', 'dst_port', 'length', 'ttl', 'id', 
                         'data_length', 'offset', 'tracker']
        for col in numeric_fields:
            if col in self.df.columns:
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
        
        # Timestamp
        if '@timestamp' in self.df.columns:
            self.df['@timestamp'] = pd.to_datetime(self.df['@timestamp'], errors='coerce')
        
        # String fields lowercase
        string_fields = ['action', 'proto_name', 'dir', 'tcp_flags']
        for col in string_fields:
            if col in self.df.columns:
                self.df[col] = self.df[col].astype(str).str.lower()
    
    def _handle_missing_values(self):
        """Xử lý missing values"""
        self.logger.info("  ↳ Xử lý missing values...")
        
        before = self.df.isnull().sum().sum()
        
        # Critical fields: xóa dòng thiếu
        critical = ['action', 'proto_name', '@timestamp']
        self.df = self.df.dropna(subset=critical)
        
        # Ports: fill 0
        for col in ['src_port', 'dst_port']:
            if col in self.df.columns:
                self.df[col].fillna(0, inplace=True)
        
        # Direction: fill 'unknown'
        if 'dir' in self.df.columns:
            self.df['dir'].fillna('unknown', inplace=True)
        
        # Numeric: fill median
        numeric_cols = ['length', 'ttl', 'data_length']
        for col in numeric_cols:
            if col in self.df.columns and self.df[col].dtype in ['int64', 'float64']:
                median = self.df[col].median()
                self.df[col].fillna(median, inplace=True)
        
        after = self.df.isnull().sum().sum()
        self.logger.info(f"    • Missing: {before:,} → {after:,}")
    
    def _handle_outliers(self):
        """Xử lý outliers bằng IQR clipping"""
        self.logger.info("  ↳ Xử lý outliers (IQR method)...")
        
        numeric_cols = ['src_port', 'dst_port', 'length', 'ttl']
        total_outliers = 0
        
        for col in numeric_cols:
            if col not in self.df.columns:
                continue
            
            Q1 = self.df[col].quantile(0.25)
            Q3 = self.df[col].quantile(0.75)
            IQR = Q3 - Q1
            
            lower = Q1 - 3 * IQR
            upper = Q3 + 3 * IQR
            
            outliers = ((self.df[col] < lower) | (self.df[col] > upper)).sum()
            total_outliers += outliers
            
            # Clip instead of remove
            self.df[col] = self.df[col].clip(lower=lower, upper=upper)
        
        if total_outliers > 0:
            self.logger.info(f"    • Đã clip {total_outliers:,} outliers")
    
    def _normalize_values(self):
        """Chuẩn hóa giá trị"""
        self.logger.info("  ↳ Chuẩn hóa giá trị...")
        
        # Lowercase các trường text
        text_cols = ['action', 'proto_name', 'dir', 'reason']
        for col in text_cols:
            if col in self.df.columns:
                self.df[col] = self.df[col].str.strip().str.lower()
        
        # Strip whitespace từ IPs
        for col in ['src_ip', 'dst_ip']:
            if col in self.df.columns:
                self.df[col] = self.df[col].str.strip()
    
    def save_processed_data(self, output_path: str):
        """
        Lưu dữ liệu đã xử lý
        
        Args:
            output_path: Đường dẫn file output (.pkl hoặc .csv)
        """
        try:
            self.logger.info(f"\n💾 Lưu dữ liệu vào: {output_path}")
            
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.endswith('.pkl'):
                self.df.to_pickle(output_path)
            elif output_path.endswith('.csv'):
                self.df.to_csv(output_path, index=False)
            else:
                raise ValueError("Chỉ hỗ trợ .pkl hoặc .csv")
            
            self.logger.success(f"✅ Đã lưu {len(self.df):,} bản ghi")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi lưu file: {str(e)}")
            raise
    
    def get_statistics(self) -> Dict:
        """Lấy thống kê dữ liệu"""
        if self.df is None:
            return {}
        
        stats = {
            'total_records': len(self.df),
            'columns': list(self.df.columns),
            'action_dist': self.df['action'].value_counts().to_dict() if 'action' in self.df.columns else {},
            'protocol_dist': self.df['proto_name'].value_counts().to_dict() if 'proto_name' in self.df.columns else {},
            'missing_values': self.df.isnull().sum().to_dict()
        }
        
        return stats
    
    def print_summary(self):
        """In tóm tắt dữ liệu đẹp"""
        self.logger.info("\n" + "="*80)
        self.logger.info("📊 TÓM TẮT DỮ LIỆU")
        self.logger.info("="*80)
        
        if self.df is None:
            self.logger.warning("Chưa có dữ liệu")
            return
        
        print(f"\n{'Tổng số bản ghi:':<30} {len(self.df):>15,}")
        print(f"{'Số cột:':<30} {len(self.df.columns):>15,}")
        
        if 'action' in self.df.columns:
            print(f"\n{'Action Distribution:':<30}")
            for action, count in self.df['action'].value_counts().items():
                pct = count / len(self.df) * 100
                print(f"  {action:<28} {count:>10,}  ({pct:>5.1f}%)")
        
        if 'proto_name' in self.df.columns:
            print(f"\n{'Protocol Distribution:':<30}")
            for proto, count in self.df['proto_name'].value_counts().head(5).items():
                pct = count / len(self.df) * 100
                print(f"  {proto:<28} {count:>10,}  ({pct:>5.1f}%)")
        
    print("\n" + "="*80 + "\n")


if __name__ == '__main__':
    import yaml
    
    with open('config/config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    processor = DataProcessor(config)
    df = processor.load_logs(config['data']['training_logs'])
    processor.validate_data()
    df_cleaned = processor.clean_data()
    processor.save_processed_data(config['data']['cleaned_logs'])
    processor.print_summary()
