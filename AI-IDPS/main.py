"""
main.py
AI-IDPS REALTIME DETECTION SYSTEM - ENTRY POINT
Entry point duy nhất của hệ thống phát hiện bất thường realtime

Chức năng:
- Load config từ config.yaml và .env
- Khởi tạo logger console UI
- Hiển thị banner khởi động hệ thống
- Khởi động anomaly detector realtime
- Giám sát trạng thái hệ thống
- Xử lý shutdown an toàn
"""

import os
import sys
import yaml
import signal
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from src.utils.logger import get_module_logger
from src.core.anomaly_detector_realtime import AnomalyDetectorRealtime


class AIIDPSSystem:
    """
    AI-IDPS System Manager - Điểm điều phối chính
    
    Nhiệm vụ:
    - Quản lý lifecycle của hệ thống
    - Giám sát trạng thái
    - Xử lý shutdown graceful
    """
    
    def __init__(self):
        """Khởi tạo hệ thống"""
        self.logger = get_module_logger("AI-IDPS")
        self.config = None
        self.detector = None
        self.system_status = "INITIALIZING"
        self.start_time = None
        
    def _load_config(self):
        """Load cấu hình từ config.yaml và .env"""
        try:
            # Load environment variables
            load_dotenv()
            self.logger.info("✅ Loaded environment variables from .env")
            
            # Load config.yaml
            config_path = 'config/config.yaml'
            if not os.path.exists(config_path):
                self.logger.error(f"❌ Không tìm thấy file config: {config_path}")
                raise FileNotFoundError(f"Config file not found: {config_path}")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            
            self.logger.success(f"✅ Loaded configuration from {config_path}")
            
            # Validate critical config
            self._validate_config()
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Lỗi load config: {str(e)}")
            return False
    
    def _validate_config(self):
        """Validate các config bắt buộc"""
        required_keys = [
            ('paths', 'model_path'),
            ('paths', 'engineer_path'),
            ('realtime', 'fetch_interval'),
            ('realtime', 'window_size'),
            ('realtime', 'slide_interval')
        ]
        
        missing = []
        for keys in required_keys:
            value = self.config
            for key in keys:
                value = value.get(key, {})
                if not value and value != 0:
                    missing.append('.'.join(keys))
                    break
        
        if missing:
            self.logger.error(f"❌ Thiếu config: {', '.join(missing)}")
            raise ValueError(f"Missing required config: {missing}")
        
        self.logger.success("✅ Config validation passed")
    
    def _print_banner(self):
        """Hiển thị banner khởi động hệ thống"""
        banner = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║          █████╗ ██╗      ██╗██████╗ ██████╗ ███████╗                        ║
║         ██╔══██╗██║      ██║██╔══██╗██╔══██╗██╔════╝                        ║
║         ███████║██║█████╗██║██║  ██║██████╔╝███████╗                        ║
║         ██╔══██║██║╚════╝██║██║  ██║██╔═══╝ ╚════██║                        ║
║         ██║  ██║██║      ██║██████╔╝██║     ███████║                        ║
║         ╚═╝  ╚═╝╚═╝      ╚═╝╚═════╝ ╚═╝     ╚══════╝                        ║
║                                                                               ║
║         🔒 AI-Powered Intrusion Detection & Prevention System                ║
║         📊 Behavior-Based Anomaly Detection using Isolation Forest           ║
║         🌐 pfSense Firewall Log Analysis                                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

        Version: {self.config['app']['version']}
        Powered by: Isolation Forest ML Model
        Mode: REALTIME DETECTION
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        print(banner)
    
    def _print_system_config(self):
        """Hiển thị cấu hình hệ thống"""
        self.logger.info("\n" + "="*80)
        self.logger.info("⚙️  SYSTEM CONFIGURATION")
        self.logger.info("="*80)
        
        # General settings
        self.logger.info("\n📋 General:")
        self.logger.info(f"   • App Name: {self.config['app']['name']}")
        self.logger.info(f"   • Version: {self.config['app']['version']}")
        self.logger.info(f"   • Debug Mode: {'ON' if self.config['app']['debug'] else 'OFF'}")
        
        # Model settings
        model_cfg = self.config['model']
        self.logger.info("\n🤖 Model:")
        self.logger.info(f"   • Type: {model_cfg['type']}")
        self.logger.info(f"   • Contamination: {model_cfg['contamination']}")
        self.logger.info(f"   • N Estimators: {model_cfg['n_estimators']}")
        self.logger.info(f"   • Max Samples: {model_cfg['max_samples']}")
        
        # Realtime settings
        rt_cfg = self.config['realtime']
        self.logger.info("\n⚡ Realtime Detection:")
        self.logger.info(f"   • Fetch Interval: {rt_cfg['fetch_interval']}s")
        self.logger.info(f"   • Batch Size: {rt_cfg['batch_size']}")
        self.logger.info(f"   • Window Size: {rt_cfg['window_size']}s")
        self.logger.info(f"   • Slide Interval: {rt_cfg['slide_interval']}s")
        self.logger.info(f"   • Min Logs/IP: {rt_cfg['min_logs_per_ip']}")
        
        # Auto-block settings
        auto_block = rt_cfg.get('auto_block', False)
        self.logger.info("\n🔒 Auto-Block:")
        self.logger.info(f"   • Status: {'ON' if auto_block else 'OFF'}")
        if auto_block:
            block_severity = rt_cfg.get('block_severity', [])
            self.logger.info(f"   • Block Severity: {', '.join(block_severity)}")
        
        # ELK settings
        elk_cfg = self.config['elk-module']
        self.logger.info("\n📊 Elasticsearch:")
        self.logger.info(f"   • Host: {os.getenv('ES_HOST')}:{os.getenv('ES_PORT')}")
        self.logger.info(f"   • Index Pattern: {elk_cfg['INDEX_PATTERN']}")
        
        # pfSense settings
        pf_cfg = self.config['pfsense']
        self.logger.info("\n🛡️  pfSense:")
        self.logger.info(f"   • Host: {os.getenv('PFSENSE_HOST_LAN')}")
        self.logger.info(f"   • Blocked Alias: {pf_cfg['blocked_alias']}")
        
        self.logger.info("\n" + "="*80 + "\n")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers cho graceful shutdown"""
        def signal_handler(sig, frame):
            self.logger.warning("\n\n⚠️  Nhận tín hiệu dừng hệ thống...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        self.logger.info("✅ Signal handlers configured")
    
    def _check_prerequisites(self):
        """Kiểm tra các điều kiện tiên quyết"""
        self.logger.info("\n🔍 Kiểm tra prerequisites...")
        
        # Check model file
        model_path = self.config['paths']['model_path']
        if not os.path.exists(model_path):
            self.logger.error(f"❌ Model không tồn tại: {model_path}")
            self.logger.error("💡 Chạy: python scripts/train_model.py")
            return False
        self.logger.success(f"✅ Model found: {model_path}")
        
        # Check engineer file
        engineer_path = self.config['paths']['engineer_path']
        if not os.path.exists(engineer_path):
            self.logger.error(f"❌ Engineer không tồn tại: {engineer_path}")
            self.logger.error("💡 Chạy: python scripts/train_model.py")
            return False
        self.logger.success(f"✅ Engineer found: {engineer_path}")
        
        # Check environment variables
        required_env = ['ES_HOST', 'ES_PORT', 'PFSENSE_HOST_LAN']
        missing_env = [var for var in required_env if not os.getenv(var)]
        if missing_env:
            self.logger.error(f"❌ Thiếu biến môi trường: {', '.join(missing_env)}")
            self.logger.error("💡 Kiểm tra file .env")
            return False
        self.logger.success("✅ Environment variables OK")
        
        return True
    
    def initialize(self):
        """Khởi tạo hệ thống"""
        try:
            self.system_status = "INITIALIZING"
            
            # Load config
            self.logger.info("🔧 Đang load configuration...")
            if not self._load_config():
                return False
            
            # Print banner
            self._print_banner()
            
            # Print system config
            self._print_system_config()
            
            # Check prerequisites
            if not self._check_prerequisites():
                return False
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            # Initialize detector
            self.logger.info("\n🚀 Khởi tạo Anomaly Detector...")
            self.detector = AnomalyDetectorRealtime(self.config)
            
            self.system_status = "INITIALIZED"
            self.start_time = datetime.now()
            
            self.logger.success("\n✅ Hệ thống đã được khởi tạo thành công!")
            return True
            
        except Exception as e:
            self.logger.error(f"\n❌ Lỗi khởi tạo hệ thống: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def start(self):
        """Khởi động hệ thống detection"""
        try:
            self.system_status = "RUNNING"
            
            self.logger.success("\n" + "="*80)
            self.logger.success("🚀 HỆ THỐNG ĐANG HOẠT ĐỘNG")
            self.logger.success("="*80)
            self.logger.info(f"   Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.logger.info(f"   Status: {self.system_status}")
            self.logger.info(f"   Press Ctrl+C to stop")
            self.logger.success("="*80 + "\n")
            
            # Start detection loop
            self.detector.start_realtime_detection()
            
        except KeyboardInterrupt:
            self.logger.warning("\n⚠️  Dừng bởi người dùng (Ctrl+C)")
        except Exception as e:
            self.logger.error(f"\n❌ Lỗi trong quá trình chạy: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown hệ thống an toàn"""
        if self.system_status == "STOPPED":
            return
        
        self.logger.info("\n" + "="*80)
        self.logger.info("🛑 ĐANG DỪNG HỆ THỐNG")
        self.logger.info("="*80)
        
        self.system_status = "STOPPED"
        
        if self.detector:
            # Print final statistics
            if hasattr(self.detector, '_print_statistics'):
                self.detector._print_statistics()
        
        if self.start_time:
            uptime = datetime.now() - self.start_time
            uptime_str = str(uptime).split('.')[0]
            self.logger.info(f"   Total Uptime: {uptime_str}")
        
        self.logger.success("\n✅ Hệ thống đã dừng an toàn")
        self.logger.info("="*80 + "\n")


def main():
    """Main entry point"""
    
    # Create system instance
    system = AIIDPSSystem()
    
    # Initialize
    if not system.initialize():
        print("\n❌ Không thể khởi tạo hệ thống. Thoát.")
        sys.exit(1)
    
    # Start
    system.start()


if __name__ == '__main__':
    main()
