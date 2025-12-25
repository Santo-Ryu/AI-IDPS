"""
scripts/anomaly_detector_realtime.py
Module phát hiện bất thường REALTIME từ pfSense logs - UPGRADED VERSION
Sử dụng Isolation Forest với cơ chế Sliding Time Window

KIẾN TRÚC:
- Fetch logs liên tục từ ELK (batch nhỏ) với PROGRESS BAR
- Gom logs theo IP trong sliding window (60s)
- Phân tích HÀNH VI tổng hợp (không phải single log)
- Console UI chuyên nghiệp với progress bars và báo cáo chi tiết
- Cảnh báo + block IP có behavior bất thường
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional
from pathlib import Path
import sys
import yaml
import pickle
from datetime import datetime, timedelta
from collections import defaultdict, deque
import time
import signal

sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_module_logger
from src.core.feature_engineer import FeatureEngineer
from src.integrations.elk_client import fetch_logs_realtime
from src.integrations.pfsense_client import pfSenseClient


class AnomalyDetectorRealtime:
    """
    Detector phát hiện bất thường REALTIME với Sliding Time Window
    
    Flow:
    1. Fetch logs từ ELK mỗi 5-20s (với progress bar)
    2. Gom logs theo IP trong window 60s
    3. Khi đủ logs (>=5), tính behavioral features
    4. Model đánh giá → nếu anomaly thì cảnh báo + block
    """
    
    def __init__(self, config: Dict):
        """Khởi tạo Anomaly Detector"""
        self.config = config
        self.logger = get_module_logger("AnomalyDetector")
        
        # === CẤU HÌNH SLIDING WINDOW ===
        rt_config = config.get('realtime', {})
        self.window_size = rt_config.get('window_size', 60)
        self.slide_interval = rt_config.get('slide_interval', 20)
        self.min_logs_per_ip = rt_config.get('min_logs_per_ip', 5)
        self.auto_block = rt_config.get('auto_block', True)
        self.block_severity = rt_config.get('block_severity', ['CRITICAL', 'HIGH'])
        
        # === STORAGE ===
        self.log_buffer = deque(maxlen=10000)
        self.ip_windows = defaultdict(list)
        self.detected_ips = {}
        self.blocked_ips = set()
        
        # === STATISTICS ===
        self.stats = {
            'total_logs_processed': 0,
            'total_detections': 0,
            'total_blocks': 0,
            'start_time': datetime.now(),
            'ips_analyzed': 0,
            'current_window_ips': 0,
            'normal_ips': 0,
            'anomaly_scores': []
        }
        
        # === MODEL & ENGINEER ===
        self.model = None
        self.engineer = None
        self.pfsense_client = None
        
        self.logger.info("="*80)
        self.logger.success("🚀 Khởi tạo Realtime Anomaly Detector")
        self.logger.info("="*80)
        self.logger.info(f"📊 Window size: {self.window_size}s")
        self.logger.info(f"⏱️  Slide interval: {self.slide_interval}s")
        self.logger.info(f"📈 Min logs/IP: {self.min_logs_per_ip}")
        self.logger.info(f"🔒 Auto block: {'ON' if self.auto_block else 'OFF'}")
        if self.auto_block:
            self.logger.info(f"   └─ Block severity: {', '.join(self.block_severity)}")
        
        self._load_model()
        self._load_engineer()
        self._init_pfsense_client()
    
    def _load_model(self):
        """Load mô hình Isolation Forest đã train"""
        try:
            model_path = self.config['paths']['model_path']
            
            if not Path(model_path).exists():
                self.logger.error(f"❌ Model không tồn tại: {model_path}")
                self.logger.error("💡 Chạy scripts/train_model.py để train model trước")
                raise FileNotFoundError(f"Model not found: {model_path}")
            
            self.logger.info(f"📦 Loading model từ: {model_path}")
            
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            self.logger.success(f"✅ Model loaded: {type(self.model).__name__}")
            self.logger.info(f"   Contamination: {self.model.contamination}")
            self.logger.info(f"   N_estimators: {self.model.n_estimators}")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi load model: {str(e)}")
            raise
    
    def _load_engineer(self):
        """Load FeatureEngineer đã fit với training data"""
        try:
            engineer_path = self.config['paths']['engineer_path']
            
            if not Path(engineer_path).exists():
                self.logger.error(f"❌ Engineer không tồn tại: {engineer_path}")
                raise FileNotFoundError(f"Engineer not found: {engineer_path}")
            
            self.logger.info(f"🔧 Loading engineer từ: {engineer_path}")
            
            with open(engineer_path, 'rb') as f:
                self.engineer = pickle.load(f)
            
            self.logger.success(f"✅ Engineer loaded: {len(self.engineer.feature_columns)} features")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi load engineer: {str(e)}")
            raise
    
    def _init_pfsense_client(self):
        """Khởi tạo pfSense SSH client để block IP"""
        try:
            self.logger.info("🔐 Khởi tạo pfSense client...")
            
            import os
            from dotenv import load_dotenv
            load_dotenv()
            
            host = os.getenv('PFSENSE_HOST_LAN')
            user = os.getenv('PFSENSE_USER')
            ssh_key = os.getenv('PFSENSE_SSH_KEY')
            table = self.config['pfsense']['blocked_alias']
            
            self.pfsense_client = pfSenseClient(
                host=host,
                user=user,
                ssh_key=ssh_key,
                table=table
            )
            
            if self.pfsense_client.check_table_exists():
                self.logger.success("✅ pfSense client sẵn sàng")
            else:
                self.logger.warning("⚠️  pfSense table chưa tồn tại - cần tạo trên pfSense")
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi init pfSense client: {str(e)}")
            self.logger.warning("⚠️  Tiếp tục KHÔNG có khả năng block IP tự động")
            self.pfsense_client = None
    
    def _add_logs_to_buffer(self, logs: List[Dict]):
        """Thêm logs mới vào buffer và windows"""
        current_time = datetime.now()
        
        for log in logs:
            ts_str = log.get('@timestamp')
            if ts_str:
                try:
                    log_time = pd.to_datetime(ts_str, utc=True)
                except:
                    log_time = current_time
            else:
                log_time = current_time
            
            log['_parsed_timestamp'] = log_time
            self.log_buffer.append(log)
            
            src_ip = log.get('src_ip')
            if src_ip:
                self.ip_windows[src_ip].append(log)
            
            self.stats['total_logs_processed'] += 1
    
    def _clean_expired_logs(self):
        """Xóa logs cũ hơn window_size khỏi ip_windows"""
        current_time = pd.Timestamp.now(tz='UTC')
        cutoff_time = current_time - timedelta(seconds=self.window_size)
        
        for ip in list(self.ip_windows.keys()):
            self.ip_windows[ip] = [
                log for log in self.ip_windows[ip]
                if log.get('_parsed_timestamp', datetime.min) >= cutoff_time
            ]
            
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]
        
        self.stats['current_window_ips'] = len(self.ip_windows)
    
    def _print_window_countdown(self, seconds_remaining: int, logs_in_buffer: int, ips_tracking: int):
        """
        Progress bar đếm ngược trong lúc chờ window
        
        Args:
            seconds_remaining: Số giây còn lại
            logs_in_buffer: Số logs đã gom
            ips_tracking: Số IP đang theo dõi
        """
        bar_length = 40
        elapsed = self.slide_interval - seconds_remaining
        percent = int(elapsed / self.slide_interval * 100)
        filled_length = int(bar_length * elapsed / self.slide_interval)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        
        # Màu sắc
        if seconds_remaining <= 3:
            color = "\033[92m"  # Green - sắp analyze
        elif seconds_remaining <= 8:
            color = "\033[93m"  # Yellow
        else:
            color = "\033[96m"  # Cyan
        reset = "\033[0m"
        
        mins, secs = divmod(seconds_remaining, 60)
        time_str = f"{mins:02d}:{secs:02d}" if mins else f"{secs:02d}s"
        
        print(f"\r🔄 Chờ phân tích: {color}[{bar}]{reset} {percent:3d}% | {color}{time_str}{reset} "
              f"| 📊 {logs_in_buffer:,} logs | 👥 {ips_tracking} IPs", 
              end="", flush=True)
    
    def _aggregate_ip_behavior(self, ip: str, logs: List[Dict]) -> Optional[pd.DataFrame]:
        """Tổng hợp HÀNH VI của 1 IP từ nhiều logs trong window"""
        try:
            if len(logs) < self.min_logs_per_ip:
                return None
            
            df = pd.DataFrame(logs)
            
            behavior = {
                'total_connections': len(df),
                'unique_dst_ips': df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0,
                'unique_dst_ports': df['dst_port'].nunique() if 'dst_port' in df.columns else 0,
                'block_ratio': (df['action'] == 'block').mean() if 'action' in df.columns else 0,
                'pass_ratio': (df['action'] == 'pass').mean() if 'action' in df.columns else 0,
                'avg_src_port': df['src_port'].mean() if 'src_port' in df.columns else 0,
                'avg_dst_port': df['dst_port'].mean() if 'dst_port' in df.columns else 0,
                'dst_port_diversity': df['dst_port'].std() if 'dst_port' in df.columns else 0,
                'high_risk_port_ratio': 0,
                'tcp_ratio': (df['proto_name'] == 'tcp').mean() if 'proto_name' in df.columns else 0,
                'udp_ratio': (df['proto_name'] == 'udp').mean() if 'proto_name' in df.columns else 0,
                'icmp_ratio': (df['proto_name'] == 'icmp').mean() if 'proto_name' in df.columns else 0,
                'avg_packet_length': df['length'].mean() if 'length' in df.columns else 0,
                'packet_length_std': df['length'].std() if 'length' in df.columns else 0,
                'avg_ttl': df['ttl'].mean() if 'ttl' in df.columns else 0,
                'connection_rate': len(df) / self.window_size,
            }
            
            if 'dst_port' in df.columns:
                high_risk_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 3306, 5432, 1433]
                behavior['high_risk_port_ratio'] = df['dst_port'].isin(high_risk_ports).mean()
            
            return pd.DataFrame([behavior])
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi aggregate behavior cho {ip}: {str(e)}")
            return None
    
    def _create_features_for_detection(self, behavior_df: pd.DataFrame, original_logs: List[Dict]) -> Optional[pd.DataFrame]:
        """Tạo features giống training từ aggregated behavior"""
        try:
            sample_log = original_logs[0]
            
            pseudo_log = {
                '@timestamp': datetime.now().isoformat(),
                'src_ip': sample_log.get('src_ip'),
                'dst_ip': 'aggregated',
                'src_port': int(behavior_df['avg_src_port'].iloc[0]),
                'dst_port': int(behavior_df['avg_dst_port'].iloc[0]),
                'proto_name': sample_log.get('proto_name', 'tcp'),
                'action': 'block' if behavior_df['block_ratio'].iloc[0] > 0.5 else 'pass',
                'dir': sample_log.get('dir', 'in'),
                'length': int(behavior_df['avg_packet_length'].iloc[0]),
                'ttl': int(behavior_df['avg_ttl'].iloc[0]),
                'reason': sample_log.get('reason', 'match'),
                'tcp_flags': sample_log.get('tcp_flags', ''),
                'window': sample_log.get('window', 0),
            }
            
            df = pd.DataFrame([pseudo_log])
            df_features = self.engineer.create_features(df)
            df_encoded = self.engineer.encode_features(df_features, fit=False)
            df_selected = self.engineer.select_features(df_encoded)
            df_scaled = self.engineer.scale_features(df_selected, fit=False)
            
            for col in behavior_df.columns:
                if col not in df_scaled.columns:
                    df_scaled[col] = behavior_df[col].iloc[0]
            
            return df_scaled
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi create features: {str(e)}")
            return None
    
    def _detect_anomaly(self, features: pd.DataFrame, ip: str, logs_count: int) -> Dict:
        """Phát hiện anomaly cho 1 IP"""
        try:
            prediction = self.model.predict(features)[0]
            score = self.model.decision_function(features)[0]
            
            is_anomaly = (prediction == -1)
            
            if score < -0.5:
                severity = "CRITICAL"
            elif score < -0.3:
                severity = "HIGH"
            elif score < -0.1:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            return {
                'ip': ip,
                'is_anomaly': is_anomaly,
                'anomaly_score': float(score),
                'severity': severity,
                'logs_count': logs_count,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi detect anomaly: {str(e)}")
            return {
                'ip': ip,
                'is_anomaly': False,
                'error': str(e)
            }
    
    def _analyze_window(self):
        """Phân tích tất cả IPs trong current window"""
        window_start_time = datetime.now() - timedelta(seconds=self.window_size)
        window_end_time = datetime.now()
        
        self.logger.info(f"\n{'═'*80}")
        self.logger.success(f"🔍 PHÂN TÍCH WINDOW - {datetime.now().strftime('%H:%M:%S')}")
        self.logger.info(f"{'═'*80}")
        
        # Thống kê window hiện tại
        total_ips_in_window = len(self.ip_windows)
        eligible_ips = sum(1 for logs in self.ip_windows.values() if len(logs) >= self.min_logs_per_ip)
        total_logs_in_window = sum(len(logs) for logs in self.ip_windows.values())
        
        self.logger.info(f"⏰ Window time:")
        self.logger.info(f"   • From: {window_start_time.strftime('%H:%M:%S')}")
        self.logger.info(f"   • To:   {window_end_time.strftime('%H:%M:%S')}")
        self.logger.info(f"   • Duration: {self.window_size}s")
        
        self.logger.info(f"\n📊 Window status:")
        self.logger.info(f"   • Total logs: {total_logs_in_window:,}")
        self.logger.info(f"   • Total IPs: {total_ips_in_window}")
        self.logger.info(f"   • Eligible IPs (>={self.min_logs_per_ip} logs): {eligible_ips}")
        self.logger.info(f"   • Already blocked: {len(self.blocked_ips)}")
        self.logger.info(f"{'─'*80}")
        
        analyzed_count = 0
        detected_count = 0
        normal_count = 0
        analysis_scores = []
        
        for ip, logs in self.ip_windows.items():
            if len(logs) < self.min_logs_per_ip or ip in self.blocked_ips:
                continue
            
            analyzed_count += 1
            
            behavior_df = self._aggregate_ip_behavior(ip, logs)
            if behavior_df is None:
                continue
            
            features = self._create_features_for_detection(behavior_df, logs)
            if features is None:
                continue
            
            result = self._detect_anomaly(features, ip, len(logs))
            analysis_scores.append(result['anomaly_score'])
            
            if result.get('is_anomaly'):
                detected_count += 1
                self._handle_detection(result, logs, behavior_df)
            else:
                normal_count += 1
        
        self.stats['ips_analyzed'] += analyzed_count
        self.stats['normal_ips'] += normal_count
        if analysis_scores:
            self.stats['anomaly_scores'].extend(analysis_scores)
        
        # Summary with statistics
        if detected_count > 0:
            self.logger.warning(f"\n⚠️  Window Analysis Summary:")
        else:
            self.logger.success(f"\n✅ Window Analysis Summary:")
        
        self.logger.info(f"   • IPs analyzed: {analyzed_count}")
        self.logger.info(f"   • Normal IPs: {normal_count}")
        self.logger.info(f"   • Anomalies detected: {detected_count}")
        
        if analysis_scores:
            avg_score = np.mean(analysis_scores)
            min_score = np.min(analysis_scores)
            self.logger.info(f"   • Avg anomaly score: {avg_score:.4f}")
            self.logger.info(f"   • Min anomaly score: {min_score:.4f}")
        
        self.logger.info(f"{'═'*80}\n")
    
    def _handle_detection(self, result: Dict, logs: List[Dict], behavior_df: pd.DataFrame):
        """Xử lý khi phát hiện anomaly"""
        ip = result['ip']
        severity = result['severity']
        score = result['anomaly_score']
        
        self.logger.security(f"\n🚨 PHÁT HIỆN BẤT THƯỜNG - {severity}")
        self.logger.security(f"   IP: {ip}")
        self.logger.security(f"   Anomaly Score: {score:.4f}")
        self.logger.security(f"   Logs Count: {result['logs_count']}")
        self.logger.security(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self._display_behavior_summary(behavior_df)
        
        self.detected_ips[ip] = result
        self.stats['total_detections'] += 1
        
        # Block IP nếu severity cao và auto_block ON
        if self.auto_block and severity in self.block_severity and self.pfsense_client:
            self._block_ip(ip, severity, score)
    
    def _display_behavior_summary(self, behavior_df: pd.DataFrame):
        """Hiển thị tóm tắt hành vi bất thường"""
        b = behavior_df.iloc[0]
        
        self.logger.info("   📈 Behavior Patterns:")
        self.logger.info(f"      • Connections: {int(b['total_connections'])}")
        self.logger.info(f"      • Target diversity: {int(b['unique_dst_ips'])} IPs, {int(b['unique_dst_ports'])} ports")
        self.logger.info(f"      • Block ratio: {b['block_ratio']:.1%}")
        self.logger.info(f"      • Connection rate: {b['connection_rate']:.2f} conn/s")
        self.logger.info(f"      • High risk ports: {b['high_risk_port_ratio']:.1%}")
        
        # Phân tích hành vi đặc biệt
        behaviors = []
        if b['unique_dst_ports'] > 50:
            behaviors.append("PORT SCANNING")
        if b['connection_rate'] > 5:
            behaviors.append("BURST TRAFFIC")
        if b['block_ratio'] > 0.7:
            behaviors.append("HIGH DROP RATE")
        if b['high_risk_port_ratio'] > 0.5:
            behaviors.append("TARGETING HIGH-RISK SERVICES")
        
        if behaviors:
            self.logger.warning(f"   ⚠️  Notable behaviors: {', '.join(behaviors)}")
    
    def _block_ip(self, ip: str, severity: str, score: float):
        """Block IP trên pfSense"""
        try:
            reason = f"AI-IDPS: Anomaly detected (Score: {score:.3f}, Severity: {severity})"
            
            self.logger.critical(f"\n🚫 BLOCKING IP: {ip}")
            self.logger.critical(f"   Reason: {reason}")
            self.logger.critical(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            result = self.pfsense_client.block_ip(
                ip=ip,
                reason=reason,
                severity=severity
            )
            
            if result.get('success'):
                self.blocked_ips.add(ip)
                self.stats['total_blocks'] += 1
                self.logger.success(f"✅ IP đã được block thành công")
            else:
                self.logger.error(f"❌ Block IP thất bại: {result.get('error')}")
                
        except Exception as e:
            self.logger.error(f"❌ Lỗi block IP: {str(e)}")
    
    def _print_statistics(self):
        """In thống kê hệ thống"""
        uptime = datetime.now() - self.stats['start_time']
        uptime_str = str(uptime).split('.')[0]
        
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"📊 SYSTEM STATISTICS")
        self.logger.info(f"{'='*80}")
        self.logger.info(f"   Uptime: {uptime_str}")
        self.logger.info(f"   Logs processed: {self.stats['total_logs_processed']:,}")
        self.logger.info(f"   IPs analyzed: {self.stats['ips_analyzed']:,}")
        self.logger.info(f"   Normal IPs: {self.stats['normal_ips']:,}")
        self.logger.info(f"   Current window IPs: {self.stats['current_window_ips']}")
        self.logger.info(f"   Total detections: {self.stats['total_detections']}")
        self.logger.info(f"   Total blocks: {self.stats['total_blocks']}")
        self.logger.info(f"{'='*80}\n")
    
    def start_realtime_detection(self):
        """Bắt đầu detection loop chính với ELK Client integration"""
        self.logger.success("\n" + "="*80)
        self.logger.success("🚀 BẮT ĐẦU REALTIME ANOMALY DETECTION")
        self.logger.success("="*80 + "\n")
        
        def signal_handler(sig, frame):
            print("\r" + " " * 100 + "\r", end="")
            self.logger.warning("\n⚠️  Nhận tín hiệu dừng...")
            self._print_statistics()
            self.logger.success("👋 Đã dừng Anomaly Detector")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Sử dụng fetch_logs_realtime từ elk_client với progress bar
            log_stream = fetch_logs_realtime(
                batch_size=self.config['realtime']['batch_size'],
                interval=self.config['realtime']['fetch_interval'],
                show_progress=True  # Bật progress bar
            )
            
            last_analysis_time = datetime.now()
            stats_counter = 0
            
            for logs_batch in log_stream:
                self._add_logs_to_buffer(logs_batch)
                self._clean_expired_logs()
                
                current_time = datetime.now()
                time_since_last_analysis = (current_time - last_analysis_time).total_seconds()
                seconds_remaining = self.slide_interval - int(time_since_last_analysis)
                
                if seconds_remaining > 0:
                    self._print_window_countdown(
                        seconds_remaining,
                        self.stats['total_logs_processed'],
                        self.stats['current_window_ips']
                    )
                
                if time_since_last_analysis >= self.slide_interval:
                    print("\r" + " " * 100 + "\r", end="")
                    self._analyze_window()
                    last_analysis_time = current_time
                    stats_counter += 1
                    
                    if stats_counter >= 10:
                        self._print_statistics()
                        stats_counter = 0
                        
        except KeyboardInterrupt:
            print("\r" + " " * 100 + "\r", end="")
            self.logger.warning("\n⚠️  Dừng bởi người dùng (Ctrl+C)")
        except Exception as e:
            self.logger.error(f"\n❌ Lỗi trong detection loop: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
        finally:
            self._print_statistics()
            self.logger.success("👋 Đã dừng Anomaly Detector")


def main():
    """Main function - Entry point"""
    print("\n" + "="*80)
    print("🔒 AI-IDPS REALTIME ANOMALY DETECTION - BEHAVIOR-BASED")
    print("="*80 + "\n")
    
    config_path = 'config/config.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    detector = AnomalyDetectorRealtime(config)
    detector.start_realtime_detection()


if __name__ == '__main__':
    main()
